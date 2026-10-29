package analytics

import (
	stdcmp "cmp"
	"context"
	"encoding/json"
	"math"
	"os"
	"reflect"
	"regexp"
	"slices"
	"strings"

	"github.com/google/go-cmp/cmp"
	"github.com/hashicorp/go-set/v3"
	"github.com/posthog/posthog-go"
	"github.com/shirou/gopsutil/v4/cpu"
	"github.com/shirou/gopsutil/v4/host"
	"github.com/shirou/gopsutil/v4/mem"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/testing/protocmp"
	"google.golang.org/protobuf/types/known/durationpb"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/version"
	configpb "github.com/pomerium/pomerium/pkg/grpc/config"
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
	p.Merge(r.CreatePosthogPropertiesForRouteSettings(cfg))
	p.Merge(r.CreatePosthogPropertiesForRuntimeFlags(cfg))
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

func (r *reporter) CreatePosthogPropertiesForRouteSettings(cfg *config.Config) posthog.Properties {
	// the values a route inherits from the global settings
	settings := cfg.Options.ToProto().Settings
	inherited := &configpb.Route{
		Timeout:                     durationpb.New(cfg.Options.DefaultUpstreamTimeout),
		PassIdentityHeaders:         settings.PassIdentityHeaders,
		JwtIssuerFormat:             settings.JwtIssuerFormat,
		JwtGroupsFilter:             settings.JwtGroupsFilter,
		JwtGroupsFilterInferFromPpl: settings.JwtGroupsFilterInferFromPpl,
		BearerTokenFormat:           settings.BearerTokenFormat,
		CircuitBreakerThresholds:    settings.CircuitBreakerThresholds,
	}
	if settings.AllowUpgrades != nil {
		inherited.AllowUpgrades = &configpb.Route_StringList{Values: settings.AllowUpgrades.Values}
	}
	if settings.IdpAccessTokenAllowedAudiences != nil {
		inherited.IdpAccessTokenAllowedAudiences = &configpb.Route_StringList{Values: settings.IdpAccessTokenAllowedAudiences.Values}
	}

	changedRouteSettings := set.NewTreeSet(strings.Compare)
	for policy := range cfg.Options.GetAllPolicies() {
		route, err := policy.ToProto()
		if err != nil {
			continue
		}
		// ToProto sets the default timeout when the route doesn't set one
		if policy.UpstreamTimeout == nil {
			route.Timeout = nil
		}
		// fields the route doesn't set inherit the global value
		inherited.ProtoReflect().Range(func(fd protoreflect.FieldDescriptor, v protoreflect.Value) bool {
			if !route.ProtoReflect().Has(fd) {
				route.ProtoReflect().Set(fd, v)
			}
			return true
		})

		for _, field := range getChangedFields(inherited, route) {
			if name := getChangedRouteSettingsName(field); name != "" {
				changedRouteSettings.Insert(name)
			}
		}
		if len(route.To) > 1 {
			changedRouteSettings.Insert("load_balancing")
		}
		if proto.Size(route.GetMcp().GetServer()) > 0 {
			changedRouteSettings.Insert("mcp")
		}
	}

	p := posthog.NewProperties()
	p["changed_route_settings"] = changedRouteSettings.Slice()
	return normalizePropertyTypes(p)
}

func (r *reporter) CreatePosthogPropertiesForRuntimeFlags(cfg *config.Config) posthog.Properties {
	defaults := config.DefaultRuntimeFlags()
	changed := []string{}
	for flag, def := range defaults {
		if cfg.Options.IsRuntimeFlagSet(flag) != def {
			changed = append(changed, string(flag))
		}
	}
	// unknown flags are ignored by pomerium, but report them without their name
	for flag := range cfg.Options.RuntimeFlags {
		if _, ok := defaults[flag]; !ok {
			changed = append(changed, "other")
			break
		}
	}
	slices.Sort(changed)

	p := posthog.NewProperties()
	p["changed_runtime_flags"] = changed
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
	// ToZerolog and ToEnvoy panic on unknown log levels, so check them first
	p["log_level"], p["proxy_log_level"] = "other", "other"
	if lvl := cfg.Options.LogLevel; config.ValidateLogLevel(lvl) == nil {
		p["log_level"] = lvl.ToZerolog().String()
	}
	// envoy uses the proxy log level, falling back to the log level and then debug
	if lvl := stdcmp.Or(cfg.Options.ProxyLogLevel, cfg.Options.LogLevel, config.LogLevelDebug); config.ValidateLogLevel(lvl) == nil {
		p["proxy_log_level"] = lvl.ToEnvoy()
	}
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
	for _, field := range getChangedFields(config.NewDefaultOptions().ToProto().Settings, cfg.Options.ToProto().Settings) {
		if name := getChangedSettingsName(field); name != "" {
			changedSettings.Insert(name)
		}
	}

	p["changed_settings"] = changedSettings.Slice()

	return normalizePropertyTypes(p)
}

// getServicesName returns the services sorted and joined with commas.
func getServicesName(services string) string {
	var names []string
	for name := range strings.SplitSeq(services, ",") {
		if name = strings.TrimSpace(strings.ToLower(name)); name != "" {
			names = append(names, name)
		}
	}
	slices.Sort(names)
	return strings.Join(slices.Compact(names), ",")
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

// getChangedFields returns the names of the top-level protobuf fields that
// differ between x and y.
func getChangedFields(x, y proto.Message) []string {
	changed := set.New[string](0)
	cmp.Equal(x, y, protocmp.Transform(),
		cmp.Reporter(&cmpReporter{callback: func(path cmp.Path, result cmp.Result) {
			if result.Equal() {
				return
			}
			// the first map index is the top-level field name
			for _, step := range path {
				if field, ok := step.(cmp.MapIndex); ok {
					if key, ok := reflect.TypeAssert[string](field.Key()); ok {
						changed.Insert(key)
					}
					return
				}
			}
		}}))
	return changed.Slice()
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
var changedSettingsRules = []fieldNameRule{
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
	{secretFieldPattern, ""},
}

// changedRouteSettingsRules map route protobuf field names to the name reported
// in changed_route_settings. Fields that match no rule are reported as themselves.
// The empty string indicates the field will be ignored.
var changedRouteSettingsRules = []fieldNameRule{
	// ignored: policies are reported in ppl_criteria, kubernetes in route_types,
	// and mcp and to are handled separately
	{`^(id|namespace_id|namespace_name|originator_id|name|stat_name|description|logo_url|from|to|allowed_users|allowed_domains|allowed_idp_claims|cors_allow_preflight|allow_public_unauthenticated_access|allow_any_authenticated_user|kubernetes_service_account_token.*|policies|ppl_policies|policy_ids|enforced_policies|assigned_policies|outlier_detection|mcp|created_at|modified_at)$`, ""},
	// groups
	{`^(prefix|path|regex|regex_priority_order|prefix_rewrite|regex_rewrite_.*)$`, "path"},
	{`^(host_rewrite|host_rewrite_header|host_path_regex_rewrite_.*|preserve_host_header)$`, "host"},
	{`^(timeout|idle_timeout)$`, "timeouts"},
	{`^tls_`, "tls"},
	{`^(set_request_headers|remove_request_headers|set_response_headers|rewrite_response_headers)$`, "headers"},
	{`^(pass_identity_headers|jwt_issuer_format|jwt_groups_filter|jwt_groups_filter_infer_from_ppl|bearer_token_format)$`, "identity_headers"},
	{`^(idp_client_id|idp_client_secret|idp_access_token_allowed_audiences|identity_providers)$`, "idp"},
	{`^(allow_websockets|allow_spdy|allow_upgrades)$`, "protocols"},
	{`^(load_balancing_policy|load_balancing_weights|healthy_panic_threshold)$`, "load_balancing"},
	{`^circuit_breaker_thresholds$`, "circuit_breaker"},
	// ignore any other secrets or keys, so new fields aren't reported by default
	{secretFieldPattern, ""},
}

// secretFieldPattern matches field names that look like secrets or keys.
const secretFieldPattern = `(^|_)secret(_|$)|(^|_)keys?(_files?)?$` //nolint:gosec // a field name pattern, not a credential

var (
	getChangedSettingsName      = newFieldNameMapper(changedSettingsRules)
	getChangedRouteSettingsName = newFieldNameMapper(changedRouteSettingsRules)
)

// A fieldNameRule maps protobuf field names matching pattern to name.
type fieldNameRule struct {
	pattern string
	name    string
}

// newFieldNameMapper returns a function which returns the name of the first
// rule matching a protobuf field name, or the field name if no rule matches.
func newFieldNameMapper(rules []fieldNameRule) func(field string) string {
	regexps := make([]*regexp.Regexp, len(rules))
	for i, rule := range rules {
		regexps[i] = regexp.MustCompile(rule.pattern)
	}
	return func(field string) string {
		for i, re := range regexps {
			if re.MatchString(field) {
				return rules[i].name
			}
		}
		return field
	}
}
