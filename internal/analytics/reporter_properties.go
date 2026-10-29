package analytics

import (
	"context"
	"encoding/json"
	"math"
	"os"
	"regexp"
	"slices"
	"strings"
	"sync"

	"github.com/google/go-cmp/cmp"
	"github.com/hashicorp/go-set/v3"
	"github.com/posthog/posthog-go"
	"github.com/shirou/gopsutil/v4/cpu"
	"github.com/shirou/gopsutil/v4/host"
	"github.com/shirou/gopsutil/v4/mem"
	"google.golang.org/protobuf/testing/protocmp"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/version"
	"github.com/pomerium/pomerium/pkg/policy/parser"
)

func (r *reporter) CreatePosthogProperties(ctx context.Context, cfg *config.Config, sessionCount, userCount int) posthog.Properties {
	p := posthog.NewProperties()
	p.Set("session_count", sessionCount).
		Set("user_count", userCount)
	p.Merge(r.CreatePosthogPropertiesForCertificates(cfg))
	if infos, err := cpu.InfoWithContext(ctx); err == nil {
		p.Merge(r.CreatePosthogPropertiesForCPU(infos))
	}
	if info, err := host.InfoWithContext(ctx); err == nil {
		p.Merge(r.CreatePosthogPropertiesForHost(info))
	}
	if info, err := mem.VirtualMemoryWithContext(ctx); err == nil {
		p.Merge(r.CreatePosthogPropertiesForMemory(info))
	}
	p.Merge(r.CreatePosthogPropertiesForPolicies(cfg))
	p.Merge(r.CreatePosthogPropertiesForProduct(cfg))
	p.Merge(r.CreatePosthogPropertiesForRoutes(cfg))
	p.Merge(r.CreatePosthogPropertiesForSettings(cfg))
	return p
}

func (r *reporter) CreatePosthogPropertiesForCertificates(cfg *config.Config) posthog.Properties {
	p := posthog.NewProperties()
	// add entity counts
	certificates, _ := cfg.AllCertificates()
	p["certificate_count"] = len(certificates)
	return p
}

func (r *reporter) CreatePosthogPropertiesForCPU(infos []cpu.InfoStat) posthog.Properties {
	p := posthog.NewProperties()
	p["cpu_count"] = len(infos)
	return p
}

func (r *reporter) CreatePosthogPropertiesForHost(info *host.InfoStat) posthog.Properties {
	p := posthog.NewProperties()
	p["os"] = info.OS
	p["platform"] = info.Platform
	p["platform_version"] = info.PlatformVersion
	p["kernel_arch"] = info.KernelArch
	p["virtualization_system"] = info.VirtualizationSystem
	return p
}

func (r *reporter) CreatePosthogPropertiesForMemory(info *mem.VirtualMemoryStat) posthog.Properties {
	p := posthog.NewProperties()
	p["mem_total_gib"] = math.Round(float64(info.Total) / (1024 * 1024 * 1024))
	return normalizePropertyTypes(p)
}

func (r *reporter) CreatePosthogPropertiesForPolicies(cfg *config.Config) posthog.Properties {
	trackedCriterionNames := set.From([]string{
		"accept",
		"authenticated_user",
		"claim",
		"client_certificate",
		"cors_preflight",
		"device",
		"domain",
		"email",
		"groups",
		"http_method",
		"http_path",
		"invalid_client_certificate",
		"mcp_tool",
		"reject",
		"source_ip",
		"ssh_access_request_approved",
		"ssh_ca",
		"ssh_publickey",
		"ssh_username",
		"ssh_username_matches_claim",
		"ssh_username_matches_email",
		"user",
	})
	getCriterionName := func(criterionName string) string {
		if trackedCriterionNames.Contains(criterionName) {
			return criterionName
		}
		return "other"
	}

	addCriteria := func(seenCriterion map[string]struct{}, rules []parser.Rule) {
		for _, rule := range rules {
			for _, criterion := range slices.Concat(nil, rule.And, rule.Nor, rule.Not, rule.Or) {
				seenCriterion[getCriterionName(criterion.Name)] = struct{}{}
			}
		}
	}
	pplOperatorUsage := map[string]int{} // operator -> number of rules
	addOperators := func(rules []parser.Rule) {
		for _, rule := range rules {
			if len(rule.And) > 0 {
				pplOperatorUsage["and"]++
			}
			if len(rule.Nor) > 0 {
				pplOperatorUsage["nor"]++
			}
			if len(rule.Not) > 0 {
				pplOperatorUsage["not"]++
			}
			if len(rule.Or) > 0 {
				pplOperatorUsage["or"]++
			}
		}
	}

	var policyCount int
	policyUsage := map[string]int{}      // attached policy id -> number of routes
	pplCriteriaUsage := map[string]int{} // criterion name -> number of routes
	for route := range cfg.Options.GetAllPolicies() {
		seenCriterion := map[string]struct{}{}

		// the inline policy, ToPPL always adds an allow rule, so only count it if it has criteria
		if rules := route.ToPPL().Rules; slices.ContainsFunc(rules, func(rule parser.Rule) bool {
			return len(rule.And)+len(rule.Nor)+len(rule.Not)+len(rule.Or) > 0
		}) {
			policyCount++
			addCriteria(seenCriterion, rules)
			addOperators(rules)
		}

		// attached policies, only count operators once per distinct policy
		for _, policy := range route.SubPolicies {
			firstUse := policy.ID == "" || policyUsage[policy.ID] == 0
			if policy.ID != "" {
				policyUsage[policy.ID]++
			}
			if firstUse {
				policyCount++
			}
			subPPL, err := parser.ParseYAML(strings.NewReader(policy.SourcePPL))
			if err != nil {
				continue
			}
			addCriteria(seenCriterion, subPPL.Rules)
			if firstUse {
				addOperators(subPPL.Rules)
			}
		}

		for criterionName := range seenCriterion {
			pplCriteriaUsage[criterionName]++
		}
	}
	var sharedPolicyCount int
	for _, count := range policyUsage {
		if count > 1 {
			sharedPolicyCount++
		}
	}
	p := posthog.NewProperties()
	p["policy_count"] = policyCount
	p["ppl_criteria"] = pplCriteriaUsage
	p["ppl_operators"] = pplOperatorUsage
	p["shared_policy_count"] = sharedPolicyCount
	return normalizePropertyTypes(p)
}

func (r *reporter) CreatePosthogPropertiesForProduct(cfg *config.Config) posthog.Properties {
	p := posthog.NewProperties()
	p["build_version"] = version.FullVersion()
	p["envoy_version"] = cfg.EnvoyVersion
	if cfg.ZeroClusterID != "" {
		p["product"] = "zero"
	} else if len(os.Args) > 0 && os.Args[0] == "manager" {
		p["product"] = "ingress-controller"
	} else {
		p["product"] = "core"
	}
	return normalizePropertyTypes(p)
}

func (r *reporter) CreatePosthogPropertiesForRoutes(cfg *config.Config) posthog.Properties {
	var routeCount int
	routeTypes := map[string]int{}
	for route := range cfg.Options.GetAllPolicies() {
		routeCount++
		if route.IsForKubernetes() {
			routeTypes["kubernetes"]++
		} else if route.IsMCPServer() {
			routeTypes["mcp_server"]++
		} else if route.IsMCPClient() {
			routeTypes["mcp_client"]++
		} else if route.IsSSH() {
			routeTypes["ssh"]++
		} else if route.IsTCP() || route.IsTCPUpstream() {
			routeTypes["tcp"]++
		} else if route.IsUDP() || route.IsUDPUpstream() {
			routeTypes["udp"]++
		} else {
			routeTypes["http"]++
		}
	}
	p := posthog.NewProperties()
	p["route_count"] = routeCount
	p["route_types"] = routeTypes
	return normalizePropertyTypes(p)
}

func (r *reporter) CreatePosthogPropertiesForSettings(cfg *config.Config) posthog.Properties {
	p := posthog.NewProperties()
	p["databroker_storage_type"] = cfg.Options.DataBroker.StorageType
	if cfg.Options.Provider != "" {
		p["identity_provider"] = cfg.Options.Provider
	} else {
		p["identity_provider"] = "none"
	}
	p["log_level"] = getLogLevelName(cfg.Options.LogLevel, func(lvl config.LogLevel) string {
		return lvl.ToZerolog().String()
	})
	// envoy uses the proxy log level, falling back to the log level and then debug
	proxyLogLevel := cfg.Options.ProxyLogLevel
	if proxyLogLevel == "" {
		proxyLogLevel = cfg.Options.LogLevel
	}
	if proxyLogLevel == "" {
		proxyLogLevel = config.LogLevelDebug
	}
	p["proxy_log_level"] = getLogLevelName(proxyLogLevel, config.LogLevel.ToEnvoy)
	switch {
	case !cfg.Options.OriginatorID.IsSet || cfg.Options.OriginatorID.Value == "":
		p["originator_id"] = "none"
	case cfg.Options.OriginatorID.Value == "local", cfg.Options.OriginatorID.Value == "terraform":
		p["originator_id"] = cfg.Options.OriginatorID.Value
	default:
		p["originator_id"] = "other"
	}
	p["services"] = getServicesName(cfg.Options.Services)

	changedSettings := set.NewTreeSet(strings.Compare)
	cmp.Equal(config.NewDefaultOptions().ToProto(), cfg.Options.ToProto(), protocmp.Transform(),
		cmp.Reporter(&cmpReporter{callback: func(path cmp.Path, result cmp.Result) {
			// nothing changed
			if result.Equal() {
				return
			}

			var name []string
			for _, step := range path {
				switch field := step.(type) {
				case cmp.MapIndex:
					if key, ok := field.Key().Interface().(string); ok {
						name = append(name, key)
					}
				}
			}

			// only global settings are tracked here, routes are handled separately
			if len(name) < 2 || name[0] != "settings" {
				return
			}

			if n := getChangedSettingsName(name[1]); n != "" {
				changedSettings.Insert(n)
			}
		}}))

	p["changed_settings"] = changedSettings.Slice()

	return normalizePropertyTypes(p)
}

// getLogLevelName returns the effective name of a log level, or "other" if
// the log level is unknown.
func getLogLevelName(lvl config.LogLevel, convert func(config.LogLevel) string) string {
	if config.ValidateLogLevel(lvl) != nil {
		return "other"
	}
	return convert(lvl)
}

// getServicesName returns "all" or the enabled services sorted and joined
// with commas.
func getServicesName(services string) string {
	if config.IsAll(services) {
		return config.ServiceAll
	}
	var names []string
	if config.IsAuthenticate(services) {
		names = append(names, config.ServiceAuthenticate)
	}
	if config.IsAuthorize(services) {
		names = append(names, config.ServiceAuthorize)
	}
	if config.IsDataBroker(services) {
		names = append(names, config.ServiceDataBroker)
	}
	if config.IsProxy(services) {
		names = append(names, config.ServiceProxy)
	}
	if len(names) == 0 {
		return "other"
	}
	return strings.Join(names, ",")
}

// normalizePropertyTypes passes the properties through json marshaling/unmarshaling so
// data is converted to standard types (like uint64 becomes float64 and map[string]int
// becomes map[string]any)
func normalizePropertyTypes(p posthog.Properties) posthog.Properties {
	if data, err := json.Marshal(p); err == nil {
		_ = json.Unmarshal(data, &p)
	}
	return p
}

type cmpReporter struct {
	path     cmp.Path
	callback func(path cmp.Path, result cmp.Result)
}

func (r *cmpReporter) PushStep(step cmp.PathStep) {
	r.path = append(r.path, step)
}

func (r *cmpReporter) PopStep() {
	r.path = r.path[:len(r.path)-1]
}

func (r *cmpReporter) Report(result cmp.Result) {
	r.callback(r.path, result)
}

// changedSettingsRules map settings protobuf field names to the name reported
// in changed_settings. Fields that match no rule are reported as themselves.
// The empty string indicates the field will be ignored.
var changedSettingsRules = []struct {
	pattern string
	name    string
}{
	// ignored
	{`^(cookie_secret|idp_client_id|autocert_eab_.*|databroker_storage_.*|log_level|proxy_log_level|services|idp_provider|certificates|certificate_key_pair_ids|runtime_flags|id|namespace_id|cluster_id|originator_id|name|installation_id|created_at|modified_at|enterprise|license_type|readonly_console_audiences|auto_apply_changesets|directory_provider.*)$`, ""},
	// renamed
	{`^scopes$`, "idp_scopes"},
	{`^request_params$`, "idp_request_params"},
	{`^derive_tls$`, "tls_derive"},
	{`^certificate_authority(_key_pair_id)?$`, "certificate_authority"},
	{`^jwt_groups_filter(_infer_from_ppl)?$`, "jwt_groups_filter"},
	// groups
	{`^autocert(_.*)?$`, "autocert"},
	{`^((darkmode_)?(primary|secondary)_color|logo_url|favicon_url|error_message_first_paragraph)$`, "branding"},
	{`^circuit_breaker_`, "circuit_breaker"},
	{`^cookie_`, "cookie"},
	{`^databroker_(cluster_|raft_)`, "databroker_cluster"},
	{`^dns_`, "dns"},
	{`^downstream_mtls$`, "downstream_mtls"},
	{`^envoy_admin_`, "envoy_admin"},
	{`^envoy_bind_config_`, "envoy_bind"},
	{`^(normalize_path|merge_slashes|path_with_escaped_slashes_action|headers_with_underscores_action)$`, "http_normalization"},
	{`_log_fields$`, "log_fields"},
	{`^mcp_`, "mcp"},
	{`^metrics_`, "metrics"},
	{`^((authorize|databroker)_service_urls|\w+_internal_service_url)$`, "service_urls"},
	{`^ssh_(address|host_key|user_ca_key|rls_)`, "ssh"},
	{`^(timeout_\w+|default_upstream_timeout|grpc_client_timeout)$`, "timeouts"},
	{`^otel_`, "tracing"},
	{`^(skip_xff_append|xff_num_trusted_hops)$`, "xff"},
	// ignore any other secrets or keys, so new fields aren't reported by default
	{`(^|_)secret(_|$)|(^|_)keys?(_files?)?$`, ""},
}

// getChangedSettingsName returns the changed_settings name for a settings
// protobuf field name.
func getChangedSettingsName(field string) string {
	for i, re := range getChangedSettingsRegexps() {
		if re.MatchString(field) {
			return changedSettingsRules[i].name
		}
	}
	return field
}

var getChangedSettingsRegexps = sync.OnceValue(func() []*regexp.Regexp {
	res := make([]*regexp.Regexp, len(changedSettingsRules))
	for i, rule := range changedSettingsRules {
		res[i] = regexp.MustCompile(rule.pattern)
	}
	return res
})
