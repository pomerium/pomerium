package analytics

import (
	"context"
	"crypto/hkdf"
	"crypto/sha256"
	"fmt"
	"time"

	"github.com/cenkalti/backoff/v4"
	"github.com/posthog/posthog-go"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/pkg/cryptutil"
	configpb "github.com/pomerium/pomerium/pkg/grpc/config"
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
		Properties: r.CreatePosthogProperties(ctx, cfg, sessionCount, userCount),
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
