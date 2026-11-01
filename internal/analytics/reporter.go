package analytics

import (
	"cmp"
	"context"
	"crypto/hkdf"
	"crypto/sha256"
	"time"

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
	config       chan *config.Config
	sessionCount chan int
	userCount    chan int
}

func New() Reporter {
	return &reporter{
		config:       make(chan *config.Config, 1),
		sessionCount: make(chan int, 1),
		userCount:    make(chan int, 1),
	}
}

func (r *reporter) CreatePosthogEvent(ctx context.Context, cfg *config.Config, sessionCount, userCount int) posthog.Capture {
	evt := posthog.Capture{
		DistinctId: cryptutil.Pseudonymize(r.getPseudonymizationKey(cfg), cmp.Or(cfg.Options.InstallationID, "posthog_distinct_id")),
		Event:      "core_periodic_analytics",
		Properties: r.CreatePosthogProperties(ctx, cfg, sessionCount, userCount),
	}
	if cfg.Options.InstallationID != "" {
		evt.Groups = posthog.Groups{"pseudonymous_installation_id": evt.DistinctId}
	}
	return evt
}

func (r *reporter) Run(ctx context.Context) {
	client, err := posthog.NewWithConfig(PostHogProductionProjectID, posthog.Config{
		Endpoint:        PostHogEndpoint,
		Logger:          posthogLogger{},
		MaxRetries:      new(9),
		ShutdownTimeout: 5 * time.Second,
	})
	if err != nil {
		log.Ctx(ctx).Err(err).Msg("analytics: failed to create posthog client")
		return
	}
	defer func() { _ = client.Close() }()

	var (
		cfg                     *config.Config
		sessionCount, userCount int
	)

	timer := time.NewTimer(initialDelay)
	defer timer.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
			timer.Reset(reportingInterval)
			if err := r.report(ctx, client, cfg, sessionCount, userCount); err != nil {
				log.Ctx(ctx).Err(err).Msg("analytics: failed to report analytics")
			}
		case sessionCount = <-r.sessionCount:
		case userCount = <-r.userCount:
		case cfg = <-r.config:
		}
	}
}

func (r *reporter) UpdateConfig(cfg *config.Config) {
	sendOrReplace(r.config, cfg)
}

func (r *reporter) UpdateUserInfo(sessionCount, userCount int) {
	sendOrReplace(r.sessionCount, sessionCount)
	sendOrReplace(r.userCount, userCount)
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

func (r *reporter) report(ctx context.Context, client posthog.Client, cfg *config.Config, sessionCount, userCount int) error {
	if cfg == nil ||
		cfg.Options.LicenseType.Value == configpb.LicenseType_LICENSE_TYPE_OPEN_SOURCE ||
		!cfg.Options.IsRuntimeFlagSet(config.RuntimeFlagProductAnalytics) {
		return nil
	}
	return client.Enqueue(r.CreatePosthogEvent(ctx, cfg, sessionCount, userCount))
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
