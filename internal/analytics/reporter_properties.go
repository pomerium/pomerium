package analytics

import (
	"context"
	"encoding/json"
	"os"
	"slices"
	"strings"

	"github.com/hashicorp/go-set/v3"
	"github.com/posthog/posthog-go"
	"github.com/shirou/gopsutil/v4/cpu"
	"github.com/shirou/gopsutil/v4/host"
	"github.com/shirou/gopsutil/v4/mem"

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
	var coreCount int
	for _, info := range infos {
		coreCount += int(info.Cores)
		p["cpu_family"] = info.Family
		p["cpu_model_name"] = info.ModelName
		p["cpu_model"] = info.Model
		p["cpu_vendor_id"] = info.VendorID
	}
	p["cpu_core_count"] = coreCount
	return p
}

func (r *reporter) CreatePosthogPropertiesForHost(info *host.InfoStat) posthog.Properties {
	p := posthog.NewProperties()
	p["os"] = info.OS
	p["platform"] = info.Platform
	p["platform_family"] = info.PlatformFamily
	p["kernel_arch"] = info.KernelArch
	p["kernel_version"] = info.KernelVersion
	p["virtualization_system"] = info.VirtualizationSystem
	return p
}

func (r *reporter) CreatePosthogPropertiesForMemory(info *mem.VirtualMemoryStat) posthog.Properties {
	p := posthog.NewProperties()
	p["mem_available_gib"] = info.Available / (1024 * 1024 * 1024)
	p["mem_total_gib"] = info.Total / (1024 * 1024 * 1024)
	p["mem_used_gib"] = info.Used / (1024 * 1024 * 1024)
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

	var inlinePolicyCount int
	policyUsage := map[string]int{}
	pplCriteriaUsage := map[string]int{} // criterion name -> count
	pplOperatorUsage := map[string]int{} // operator -> count
	for route := range cfg.Options.GetAllPolicies() {
		seenCriterion := map[string]struct{}{}
		ppl := route.ToPPL()
		if len(ppl.Rules) > 0 {
			inlinePolicyCount++
		}
		for _, rule := range ppl.Rules {
			pplOperatorUsage["and"] += len(rule.And)
			pplOperatorUsage["nor"] += len(rule.Nor)
			pplOperatorUsage["not"] += len(rule.Not)
			pplOperatorUsage["or"] += len(rule.Or)
			for _, criterion := range slices.Concat(nil, rule.And, rule.Nor, rule.Not, rule.Or) {
				seenCriterion[getCriterionName(criterion.Name)] = struct{}{}
			}
		}
		for _, policy := range route.SubPolicies {
			if policy.ID != "" {
				policyUsage[policy.ID]++
			}
			if subPPL, err := parser.ParseYAML(strings.NewReader(policy.SourcePPL)); err == nil {
				for _, rule := range subPPL.Rules {
					pplOperatorUsage["and"] += len(rule.And)
					pplOperatorUsage["nor"] += len(rule.Nor)
					pplOperatorUsage["not"] += len(rule.Not)
					pplOperatorUsage["or"] += len(rule.Or)
					for _, criterion := range slices.Concat(nil, rule.And, rule.Nor, rule.Not, rule.Or) {
						seenCriterion[getCriterionName(criterion.Name)] = struct{}{}
					}
				}
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
	p["policy_count"] = inlinePolicyCount + len(policyUsage)
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
		p["zero_cluster_id"] = cfg.ZeroClusterID
		p["zero_organization_id"] = cfg.ZeroOrganizationID
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
		} else if route.IsMCPClient() {
			routeTypes["mcp_client"]++
		} else if route.IsMCPServer() {
			routeTypes["mcp_server"]++
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
	p["log_level"] = cfg.Options.LogLevel
	p["proxy_log_level"] = cfg.Options.ProxyLogLevel
	r.setPII(cfg, p, "identity_provider_url", cfg.Options.ProviderURL)
	if !cfg.Options.OriginatorID.IsSet {
		p["originator_id"] = "local"
	} else if cfg.Options.OriginatorID.Value == "terraform" {
		p["originator_id"] = "terraform"
	} else {
		p["originator_id"] = "other"
	}
	p["services"] = cfg.Options.Services
	return normalizePropertyTypes(p)
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
