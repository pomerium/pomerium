package analytics

import (
	"cmp"
	"context"
	"crypto/hkdf"
	"crypto/sha256"
	"fmt"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/cenkalti/backoff/v4"
	"github.com/google/uuid"
	"github.com/hashicorp/go-set/v3"
	"github.com/posthog/posthog-go"
	"github.com/shirou/gopsutil/v4/cpu"
	"github.com/shirou/gopsutil/v4/host"
	"github.com/shirou/gopsutil/v4/mem"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/internal/urlutil"
	"github.com/pomerium/pomerium/internal/version"
	"github.com/pomerium/pomerium/pkg/cryptutil"
	configpb "github.com/pomerium/pomerium/pkg/grpc/config"
	"github.com/pomerium/pomerium/pkg/policy/parser"
)

var fallbackKey = cryptutil.NewKey()

type Reporter interface {
	CreatePosthogEvent(ctx context.Context, cfg *config.Config, sessionCount, userCount int) posthog.Capture
	Run(ctx context.Context)
	UpdateUserInfo(sessionCount, userCount int)
	UpdateConfig(cfg *config.Config)
}

type reporter struct {
	cfg *reporterConfig

	config       chan *config.Config
	sessionCount chan int
	userCount    chan int
}

func New(options ...ReporterOption) Reporter {
	return &reporter{
		cfg: getReporterConfig(options...),

		config:       make(chan *config.Config, 1),
		sessionCount: make(chan int, 1),
		userCount:    make(chan int, 1),
	}
}

func (r *reporter) CreatePosthogEvent(ctx context.Context, cfg *config.Config, sessionCount, userCount int) posthog.Capture {
	evt := posthog.Capture{
		DistinctId: r.getDistinctID(cfg),
		Event:      "core_periodic_analytics",
		Properties: r.createPosthogProperties(ctx, cfg, sessionCount, userCount),
	}
	if cfg.Options.InstallationID != "" {
		evt.Groups = make(posthog.Groups)
		r.setPII(cfg, evt.Groups, "installation_id", cfg.Options.InstallationID)
	}
	return evt
}

func (r *reporter) Run(ctx context.Context) {
	var (
		cfg                     *config.Config
		sessionCount, userCount int
	)

	initialTimer := time.After(r.cfg.initialDelay)
	var reportingTicker <-chan time.Time
	shouldReport := false

	bo := backoff.NewExponentialBackOff(backoff.WithMaxElapsedTime(0))
	var backoffTimer <-chan time.Time

	for {
		select {
		case <-ctx.Done():
			return
		case <-initialTimer:
			reportingTicker = time.Tick(r.cfg.reportingInterval)
			shouldReport = true
		case <-backoffTimer:
			shouldReport = true
		case <-reportingTicker:
			shouldReport = true
		case sessionCount = <-r.sessionCount:
		case userCount = <-r.userCount:
		case cfg = <-r.config:
		}

		if shouldReport {
			err := r.report(ctx, cfg, sessionCount, userCount)
			if err == nil {
				bo.Reset()
				backoffTimer = nil
			} else {
				log.Ctx(ctx).Err(err).Msg("analytics: failed to report analytics")
				backoffTimer = time.After(bo.NextBackOff())
			}
		}
		shouldReport = false
	}
}

func (r *reporter) UpdateConfig(cfg *config.Config) {
	sendOrReplace(r.config, cfg)
}

func (r *reporter) UpdateUserInfo(sessionCount, userCount int) {
	sendOrReplace(r.sessionCount, sessionCount)
	sendOrReplace(r.userCount, userCount)
}

func (r *reporter) createPosthogProperties(ctx context.Context, cfg *config.Config, sessionCount, userCount int) posthog.Properties {
	p := posthog.NewProperties()
	p.Set("session_count", sessionCount).
		Set("user_count", userCount)
	p.Merge(r.createPosthogPropertiesForCertificates(cfg))
	p.Merge(r.createPosthogPropertiesForCPU(ctx))
	p.Merge(r.createPosthogPropertiesForCriteria(cfg))
	p.Merge(r.createPosthogPropertiesForHost(ctx, cfg))
	p.Merge(r.createPosthogPropertiesForMemory(ctx))
	p.Merge(r.createPosthogPropertiesForPolicies(cfg))
	p.Merge(r.createPosthogPropertiesForProduct(cfg))
	p.Merge(r.createPosthogPropertiesForRoutes(cfg))
	p.Merge(r.createPosthogPropertiesForSettings(cfg))
	return p
}

func (r *reporter) createPosthogPropertiesForCertificates(cfg *config.Config) posthog.Properties {
	p := posthog.NewProperties()
	// add entity counts
	certificates, _ := cfg.AllCertificates()
	p["certificate_count"] = len(certificates)
	return p
}

func (r *reporter) createPosthogPropertiesForCPU(ctx context.Context) posthog.Properties {
	p := posthog.NewProperties()
	// add cpu info
	if infos, err := cpu.InfoWithContext(ctx); err == nil {
		p["cpu_count"] = len(infos)
		var coreCount int
		for _, info := range infos {
			coreCount += int(info.Cores)
			p["cpu_vendor_id"] = info.VendorID
			p["cpu_family"] = info.Family
			p["cpu_model"] = info.Model
			p["cpu_model_name"] = info.ModelName
		}
		p["cpu_core_count"] = coreCount
	}
	return p
}

func (r *reporter) createPosthogPropertiesForCriteria(cfg *config.Config) posthog.Properties {
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

	routeCriteriaCounts := map[string]map[string]struct{}{}
	policyCriteriaCounts := map[string]map[string]struct{}{}
	visitCriterion := func(routeID, policyID, criterionName string) {
		if !trackedCriterionNames.Contains(criterionName) {
			criterionName = "other"
		}

		m, ok := routeCriteriaCounts[criterionName]
		if !ok {
			m = make(map[string]struct{})
			routeCriteriaCounts[criterionName] = m
		}
		m[routeID] = struct{}{}

		if policyID != "" {
			m, ok := policyCriteriaCounts[criterionName]
			if !ok {
				m = make(map[string]struct{})
				policyCriteriaCounts[criterionName] = m
			}
			m[policyID] = struct{}{}
		}
	}
	policiesWithRego := map[string]struct{}{}
	policiesWithParseErrors := map[string]struct{}{}
	for route := range cfg.Options.GetAllPolicies() {
		routeID := route.ID
		if routeID == "" {
			routeID = uuid.NewString()
		}
		ppl := route.ToPPL()
		for _, rule := range ppl.Rules {
			for _, criterion := range slices.Concat(nil, rule.And, rule.Nor, rule.Not, rule.Or) {
				visitCriterion(routeID, "", criterion.Name)
			}
		}
		for _, policy := range route.SubPolicies {
			if policy.SourcePPL != "" {
				ppl, err := parser.New().ParseYAML(strings.NewReader(policy.SourcePPL))
				if err == nil {
					for _, rule := range ppl.Rules {
						for _, criterion := range slices.Concat(nil, rule.And, rule.Nor, rule.Not, rule.Or) {
							visitCriterion(routeID, policy.ID, criterion.Name)
						}
					}
				} else if policy.ID != "" {
					policiesWithParseErrors[policy.ID] = struct{}{}
				}
			} else if policy.ID != "" && len(policy.Rego) > 0 {
				policiesWithRego[policy.ID] = struct{}{}
			}
		}
	}
	p := posthog.Properties{}
	for name, ids := range routeCriteriaCounts {
		p["routes_with_criterion_"+name+"_count"] = len(ids)
	}
	for name, ids := range policyCriteriaCounts {
		p["policies_with_criterion_"+name+"_count"] = len(ids)
	}
	p["policies_with_parse_errors"] = len(policiesWithParseErrors)
	p["policies_with_rego"] = len(policiesWithRego)
	return p
}

func (r *reporter) createPosthogPropertiesForHost(ctx context.Context, cfg *config.Config) posthog.Properties {
	p := posthog.NewProperties()
	if info, err := host.InfoWithContext(ctx); err == nil {
		r.setPII(cfg, p, "hostname", info.Hostname)
		r.setPII(cfg, p, "host_id", info.HostID)
		p.
			Set("os", info.OS).
			Set("platform", info.Platform).
			Set("platform_family", info.PlatformFamily).
			Set("platform_version", info.PlatformVersion).
			Set("kernel_arch", info.KernelArch).
			Set("kernel_version", info.KernelVersion).
			Set("virtualization_system", info.VirtualizationSystem)
	}
	return p
}

func (r *reporter) createPosthogPropertiesForMemory(ctx context.Context) posthog.Properties {
	p := posthog.NewProperties()
	if info, err := mem.VirtualMemoryWithContext(ctx); err == nil {
		p.
			Set("mem_total", info.Total).
			Set("mem_available", info.Available).
			Set("mem_used", info.Used)
	}
	return p
}

func (r *reporter) createPosthogPropertiesForProduct(cfg *config.Config) posthog.Properties {
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
	return p
}

func (r *reporter) createPosthogPropertiesForPolicies(cfg *config.Config) posthog.Properties {
	// Count a route's own non-empty PPL or legacy allow rules as its inline policy.
	// Count resolved SubPolicies as attached policies. Use policy ids locally to count
	// sharing across routes; never transmit them or their hashes. Where no id exists,
	// keep policy identity local to that route and mark that cross-route sharing cannot
	// be established. A generated rule with no criterion is not a policy.
	//
	// Report policy_count, inline_policy_count, attached_policy_count, shared_policy_count,
	// route_policy_attachment_count, and max_routes_per_policy. Add route counts for
	// inline/attached policies and a fixed histogram of zero, one, two-to-four, or
	// five-plus policies per route. Explanation and remediation contribute presence counts
	// only.
	var policyCount, inlinePolicyCount, attachedPolicyCount, routePolicyAttachmentCount int
	routesPerPolicy := map[string]int{}
	for route := range cfg.Options.GetAllPolicies() {
		ppl := route.ToPPL()
		if len(ppl.Rules) > 0 {
			inlinePolicyCount++
			policyCount++
		}
		for _, policy := range route.SubPolicies {
			if policy.ID != "" {
				routesPerPolicy[policy.ID]++
			}
			attachedPolicyCount++
		}
	}
	maxRoutesPerPolicy := 0
	for _, count := range routesPerPolicy {
		maxRoutesPerPolicy = max(maxRoutesPerPolicy, count)
	}
	return posthog.Properties{
		"policy_count":                  policyCount,
		"inline_policy_count":           inlinePolicyCount,
		"attached_policy_count":         attachedPolicyCount,
		"shared_policy_count":           len(routesPerPolicy),
		"route_policy_attachment_count": routePolicyAttachmentCount, // not sure what routePolicyAttachmentCount means
		"max_routes_per_policy":         maxRoutesPerPolicy,
	}
}

func (r *reporter) createPosthogPropertiesForRoutes(cfg *config.Config) posthog.Properties {
	domains := set.NewTreeSet(func(x, y string) int {
		return cmp.Or(
			cmp.Compare(strings.Count(x, "."), strings.Count(y, ".")),
			strings.Compare(x, y),
		)
	})
	criteria := set.NewTreeSet(strings.Compare)
	var routeCount, kubernetesCount, mcpCount, sshCount, tcpCount, udpCount int
	for route := range cfg.Options.GetAllPolicies() {
		routeCount++
		if route.IsForKubernetes() {
			kubernetesCount++
		} else if route.IsMCPClient() || route.IsMCPServer() {
			mcpCount++
		} else if route.IsSSH() {
			sshCount++
		} else if route.IsTCP() || route.IsTCPUpstream() {
			tcpCount++
		} else if route.IsUDP() || route.IsUDPUpstream() {
			udpCount++
		}
		if fromURL, err := urlutil.ParseAndValidateURL(route.From); err == nil {
			for _, domain := range urlutil.GetServerNamesForURL(fromURL) {
				if domains.Insert(domain) && domains.Size() > r.cfg.maxDomains {
					domains.Remove(domains.Max())
				}
			}
		}
		ppl := route.ToPPL()
		for _, rule := range ppl.Rules {
			for _, criterion := range rule.And {
				criteria.Insert(criterion.Name)
			}
			for _, criterion := range rule.Or {
				criteria.Insert(criterion.Name)
			}
			for _, criterion := range rule.Nor {
				criteria.Insert(criterion.Name)
			}
			for _, criterion := range rule.Not {
				criteria.Insert(criterion.Name)
			}
		}
	}
	p := posthog.Properties{
		"ppl_criteria":           criteria.Slice(),
		"route_count":            routeCount,
		"kubernetes_route_count": kubernetesCount,
		"mcp_route_count":        mcpCount,
		"ssh_route_count":        sshCount,
		"tcp_route_count":        tcpCount,
		"udp_route_count":        udpCount,
	}
	r.setPIISlice(cfg, p, "domains", domains.Slice())
	return p
}

func (r *reporter) createPosthogPropertiesForSettings(cfg *config.Config) posthog.Properties {
	p := posthog.Properties{
		"identity_provider": cfg.Options.Provider,
		"originator_id":     cfg.Options.OriginatorID.Value,
	}
	r.setPII(cfg, p, "identity_provider_url", cfg.Options.ProviderURL)
	return p
}

func (r *reporter) getDistinctID(cfg *config.Config) string {
	if cfg.Options.InstallationID != "" {
		if r.shouldPseudonymize(cfg) {
			return cryptutil.Pseudonymize(r.getPseudonymizationKey(cfg), cfg.Options.InstallationID)
		}
		return cfg.Options.InstallationID
	}
	return cryptutil.Pseudonymize(r.getPseudonymizationKey(cfg), "posthog_distinct_id")
}

func (r *reporter) getPseudonymizationKey(cfg *config.Config) []byte {
	sharedKey, err := cfg.Options.GetSharedKey()
	if err != nil {
		sharedKey = fallbackKey
	}

	pseudonymizationKey, err := hkdf.Key(sha256.New, sharedKey, nil, "core_periodic_analytics", 32)
	if err != nil {
		pseudonymizationKey = fallbackKey
	}

	return pseudonymizationKey
}

func (r *reporter) report(ctx context.Context, cfg *config.Config, sessionCount, userCount int) error {
	if cfg == nil ||
		cfg.Options.LicenseType.Value == configpb.LicenseType_LICENSE_TYPE_OPEN_SOURCE ||
		!cfg.Options.IsRuntimeFlagSet(config.RuntimeFlagProductAnalytics) {
		return nil
	}

	msg := r.CreatePosthogEvent(ctx, cfg, sessionCount, userCount)

	client, err := posthog.NewWithConfig(PostHogProductionProjectID, posthog.Config{
		Endpoint: PostHogEndpoint,
		Logger:   posthogLogger{},
	})
	if err != nil {
		return fmt.Errorf("error creating posthog client: %w", err)
	}
	err = client.Enqueue(msg)
	if err != nil {
		return fmt.Errorf("error enqueing posthog capture: %w", err)
	}
	err = client.CloseWithContext(ctx)
	if err != nil {
		return fmt.Errorf("error closing posthog client: %w", err)
	}
	return nil
}

func (r *reporter) setPII[M interface{ ~map[string]any }](cfg *config.Config, dst M, key, value string) {
	if r.shouldPseudonymize(cfg) {
		dst["pseudonymous_"+key] = cryptutil.Pseudonymize(r.getPseudonymizationKey(cfg), value)
	} else {
		dst[key] = value
	}
}

func (r *reporter) setPIISlice[M interface{ ~map[string]any }](cfg *config.Config, dst M, key string, values []string) {
	if r.shouldPseudonymize(cfg) {
		pseudonymizationKey := r.getPseudonymizationKey(cfg)
		pseudonymized := make([]string, len(values))
		for i, value := range values {
			pseudonymized[i] = cryptutil.Pseudonymize(pseudonymizationKey, value)
		}
		dst["pseudonymous_"+key] = pseudonymized
	} else {
		dst[key] = values
	}
}

func (r *reporter) shouldPseudonymize(cfg *config.Config) bool {
	return cfg.Options.LicenseType.Value != configpb.LicenseType_LICENSE_TYPE_COMMERCIAL &&
		cfg.Options.LicenseType.Value != configpb.LicenseType_LICENSE_TYPE_COMMERCIAL_TRIAL
}

func sendOrReplace[T any](ch chan T, value T) {
	for {
		select {
		case <-ch:
		default:
		}
		select {
		case ch <- value:
			return
		default:
		}
	}
}
