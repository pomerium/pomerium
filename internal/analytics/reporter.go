package analytics

import (
	"cmp"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"fmt"
	"strings"
	"time"
	"uuid"

	"github.com/cenkalti/backoff/v4"
	"github.com/hashicorp/go-set/v3"
	"github.com/posthog/posthog-go"
	"github.com/shirou/gopsutil/v4/cpu"
	"github.com/shirou/gopsutil/v4/host"
	"github.com/shirou/gopsutil/v4/mem"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/internal/urlutil"
)

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
		evt.Groups = posthog.NewGroups().Set("installation_id", cfg.Options.InstallationID)
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
	p.Merge(r.createPosthogPropertiesForRoutes(cfg))

	// add entity counts
	certificates, _ := cfg.AllCertificates()
	p.
		Set("certificate_count", len(certificates))

	// add cpu info
	if infos, err := cpu.InfoWithContext(ctx); err == nil {
		var cpuCount, coreCount int
		for _, info := range infos {
			cpuCount += int(info.CPU)
			coreCount += int(info.Cores)
			p.
				Set("cpu_vendor_id", info.VendorID).
				Set("cpu_family", info.Family).
				Set("cpu_model", info.Model).
				Set("cpu_model_name", info.ModelName)
		}
		p.
			Set("cpu_count", cpuCount).
			Set("cpu_core_count", coreCount)
	}

	// add host info
	if info, err := host.InfoWithContext(ctx); err == nil {
		p.
			Set("host_id", info.HostID).
			Set("hostname", info.Hostname).
			Set("os", info.OS).
			Set("platform", info.Platform).
			Set("platform_family", info.PlatformFamily).
			Set("platform_version", info.PlatformVersion).
			Set("kernel_arch", info.KernelArch).
			Set("kernel_version", info.KernelVersion).
			Set("virtualization_system", info.VirtualizationSystem)
	}

	// add memory info
	if info, err := mem.VirtualMemoryWithContext(ctx); err == nil {
		p.
			Set("mem_total", info.Total).
			Set("mem_available", info.Available).
			Set("mem_used", info.Used)
	}

	return p
}

func (r *reporter) createPosthogPropertiesForRoutes(cfg *config.Config) posthog.Properties {
	domains := set.NewTreeSet(func(x, y string) int {
		return cmp.Or(
			cmp.Compare(strings.Count(x, "."), strings.Count(y, ".")),
			strings.Compare(x, y),
		)
	})
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
			for _, domain := range urlutil.GetDomainsForURL(fromURL, !cfg.Options.IsRuntimeFlagSet(config.RuntimeFlagMatchAnyIncomingPort)) {
				if domains.Insert(domain) && domains.Size() > r.cfg.maxDomains {
					domains.Remove(domains.Max())
				}
			}
		}
	}
	return posthog.Properties{
		"domains":                domains.Slice(),
		"route_count":            routeCount,
		"kubernetes_route_count": kubernetesCount,
		"mcp_route_count":        mcpCount,
		"ssh_route_count":        sshCount,
		"tcp_route_count":        tcpCount,
		"udp_route_count":        udpCount,
	}
}

func (r *reporter) getDistinctID(cfg *config.Config) string {
	if cfg.Options.InstallationID != "" {
		return cfg.Options.InstallationID
	}

	sharedKey, err := cfg.Options.GetSharedKey()
	if err != nil {
		return uuid.New().String()
	}

	h := hmac.New(sha256.New, sharedKey)
	h.Write([]byte("posthog-distinct-id"))
	return fmt.Sprintf("%x", h.Sum(nil))
}

func (r *reporter) report(ctx context.Context, cfg *config.Config, sessionCount, userCount int) error {
	if cfg == nil || !cfg.Options.IsRuntimeFlagSet(config.RuntimeFlagProductAnalytics) {
		return nil
	}

	msg := posthog.Capture{
		DistinctId: r.getDistinctID(cfg),
		Event:      "core_periodic_analytics",
		Properties: r.createPosthogProperties(ctx, cfg, sessionCount, userCount),
	}
	if cfg.Options.InstallationID != "" {
		msg.Groups = posthog.NewGroups().Set("installation_id", cfg.Options.InstallationID)
	}

	client, err := posthog.NewWithConfig(PostHogProductionProjectID, posthog.Config{
		Logger: posthogLogger{},
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
