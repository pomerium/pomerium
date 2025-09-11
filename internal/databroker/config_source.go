package databroker

import (
	"context"
	"fmt"
	"maps"
	"slices"
	"sync"
	"time"

	"go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc"
	oteltrace "go.opentelemetry.io/otel/trace"
	"golang.org/x/sync/errgroup"
	googlegrpc "google.golang.org/grpc"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/errgrouputil"
	"github.com/pomerium/pomerium/internal/hashutil"
	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/internal/telemetry/metrics"
	"github.com/pomerium/pomerium/pkg/cryptutil"
	"github.com/pomerium/pomerium/pkg/grpc"
	configpb "github.com/pomerium/pomerium/pkg/grpc/config"
	databrokerpb "github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/grpcutil"
	"github.com/pomerium/pomerium/pkg/health"
	"github.com/pomerium/pomerium/pkg/telemetry/trace"
)

// ConfigSource provides a new Config source that decorates an underlying config with
// configuration derived from the data broker.
type ConfigSource struct {
	mu                     sync.RWMutex
	outboundGRPCConnection *grpc.CachedOutboundGRPClientConn
	computedConfig         *config.Config
	underlyingConfig       *config.Config
	dbConfigs              map[string]dbConfig
	updaterHash            uint64
	cancel                 func()
	enableValidation       bool
	tracerProvider         oteltrace.TracerProvider

	config.ChangeDispatcher
}

type dbConfig struct {
	*configpb.Config
	version uint64
}

// EnableConfigValidation is a type that can be used to enable config validation.
type EnableConfigValidation bool

// NewConfigSource creates a new ConfigSource.
func NewConfigSource(
	ctx context.Context,
	tracerProvider oteltrace.TracerProvider,
	underlying config.Source,
	enableValidation EnableConfigValidation,
	listeners ...config.ChangeListener,
) *ConfigSource {
	src := &ConfigSource{
		tracerProvider:         tracerProvider,
		enableValidation:       bool(enableValidation),
		dbConfigs:              map[string]dbConfig{},
		outboundGRPCConnection: new(grpc.CachedOutboundGRPClientConn),
	}
	for _, li := range listeners {
		src.OnConfigChange(ctx, li)
	}
	underlying.OnConfigChange(ctx, func(ctx context.Context, cfg *config.Config) {
		src.mu.Lock()
		src.underlyingConfig = cfg.Clone()
		src.mu.Unlock()

		src.rebuild(ctx, firstTime(false))
	})
	src.underlyingConfig = underlying.GetConfig()
	src.rebuild(ctx, firstTime(true))
	return src
}

// GetConfig gets the current config.
func (src *ConfigSource) GetConfig() *config.Config {
	src.mu.RLock()
	defer src.mu.RUnlock()

	return src.computedConfig
}

type firstTime bool

func (src *ConfigSource) rebuild(ctx context.Context, firstTime firstTime) {
	_, span := trace.Continue(ctx, "databroker.config_source.rebuild")
	defer span.End()

	now := time.Now()
	src.mu.Lock()
	defer src.mu.Unlock()
	log.Ctx(ctx).Debug().Str("lock-wait", time.Since(now).String()).Msg("databroker: rebuilding configuration")

	cfg := src.underlyingConfig.Clone()

	// start the updater
	src.runUpdater(ctx, cfg)

	now = time.Now()
	err := src.buildNewConfigLocked(ctx, cfg)
	if err != nil {
		health.ReportError(health.BuildDatabrokerConfig, err)
		log.Ctx(ctx).Error().Err(err).Msg("databroker: failed to build new config")
		return
	}
	health.ReportRunning(health.BuildDatabrokerConfig)
	log.Ctx(ctx).Debug().Str("elapsed", time.Since(now).String()).Msg("databroker: built new config")

	src.computedConfig = cfg
	if !firstTime {
		src.Trigger(ctx, cfg)
	}

	metrics.SetConfigInfo(ctx, cfg.Options.Services, "databroker", cfg.Checksum(), true)
}

func (src *ConfigSource) buildNewConfigLocked(ctx context.Context, cfg *config.Config) error {
	eg, ctx := errgroup.WithContext(ctx)
	eg.Go(func() error {
		src.applySettingsLocked(ctx, cfg)
		err := cfg.Options.Validate()
		if err != nil {
			return fmt.Errorf("validating settings: %w", err)
		}
		return nil
	})

	var policyBuilders []errgrouputil.BuilderFunc[config.Policy]
	for _, cfgpb := range src.dbConfigs {
		for _, routepb := range cfgpb.GetRoutes() {
			policyBuilders = append(policyBuilders, func(ctx context.Context) (*config.Policy, error) {
				p, err := src.buildPolicyFromProto(ctx, routepb)
				if err != nil {
					return nil, fmt.Errorf("error building route id=%s: %w", routepb.GetId(), err)
				}
				return p, nil
			})
		}
	}

	var policies []*config.Policy
	eg.Go(func() error {
		var errs []error
		policies, errs = errgrouputil.Build(ctx, policyBuilders...)
		if len(errs) > 0 {
			for _, err := range errs {
				log.Ctx(ctx).Error().Msg(err.Error())
			}
			return fmt.Errorf("error building policies")
		}
		return nil
	})

	err := eg.Wait()
	if err != nil {
		return err
	}

	src.addPolicies(ctx, cfg, policies)
	return nil
}

func (src *ConfigSource) applySettingsLocked(ctx context.Context, cfg *config.Config) {
	ids := slices.Sorted(maps.Keys(src.dbConfigs))

	var certsIndex *cryptutil.CertificatesIndex
	if src.enableValidation {
		certsIndex = cryptutil.NewCertificatesIndex()
		for _, cert := range cfg.Options.GetX509Certificates() {
			certsIndex.Add(cert)
		}
	}

	for i := 0; i < len(ids) && ctx.Err() == nil; i++ {
		cfgpb := src.dbConfigs[ids[i]]
		cfg.Options.ApplySettings(ctx, certsIndex, cfgpb.Settings)
	}
}

func (src *ConfigSource) buildPolicyFromProto(_ context.Context, routepb *configpb.Route) (*config.Policy, error) {
	policy, err := config.NewPolicyFromProto(routepb)
	if err != nil {
		return nil, fmt.Errorf("error building policy from protobuf: %w", err)
	}

	if !src.enableValidation {
		return policy, nil
	}

	err = policy.Validate()
	if err != nil {
		return nil, fmt.Errorf("error validating policy: %w", err)
	}

	return policy, nil
}

func (src *ConfigSource) addPolicies(ctx context.Context, cfg *config.Config, policies []*config.Policy) {
	seen := make(map[string]struct{}, len(policies)+cfg.Options.NumPolicies())
	for policy := range cfg.Options.GetAllPolicies() {
		id, err := policy.RouteID()
		if err != nil {
			log.Ctx(ctx).Err(err).Str("policy", policy.String()).Msg("databroker: error getting route id")
			continue
		}
		seen[id] = struct{}{}
	}

	additionalPolicies := make([]config.Policy, 0, len(policies))
	for _, policy := range policies {
		if policy == nil {
			continue
		}

		id, err := policy.RouteID()
		if err != nil {
			log.Ctx(ctx).Err(err).Str("policy", policy.String()).Msg("databroker: error getting route id")
			continue
		}
		if _, ok := seen[id]; ok {
			log.Ctx(ctx).Debug().Str("policy", policy.String()).Msg("databroker: policy already exists")
			continue
		}
		additionalPolicies = append(additionalPolicies, *policy)
		seen[id] = struct{}{}
	}

	config.SortPolicies(additionalPolicies)

	// add the additional policies here since calling `Validate` will reset them.
	cfg.Options.AdditionalPolicies = append(cfg.Options.AdditionalPolicies, additionalPolicies...)
}

func (src *ConfigSource) runUpdater(ctx context.Context, cfg *config.Config) {
	sharedKey, _ := cfg.Options.GetSharedKey()
	connectionOptions := &grpc.OutboundOptions{
		OutboundPort:   cfg.OutboundPort,
		InstallationID: cfg.Options.InstallationID,
		ServiceName:    cfg.Options.Services,
		SignedJWTKey:   sharedKey,
	}
	h, err := hashutil.Hash(connectionOptions)
	if err != nil {
		log.Fatal().Err(err).Send()
	}
	// nothing changed, so don't restart the updater
	if src.updaterHash == h {
		return
	}
	src.updaterHash = h

	if src.cancel != nil {
		src.cancel()
		src.cancel = nil
	}

	ctx, src.cancel = context.WithCancel(ctx)

	cc, err := src.outboundGRPCConnection.Get(ctx, connectionOptions,
		googlegrpc.WithStatsHandler(otelgrpc.NewClientHandler(otelgrpc.WithTracerProvider(src.tracerProvider))))
	if err != nil {
		log.Ctx(ctx).Error().Err(err).Msg("databroker: failed to create gRPC connection to data broker")
		return
	}

	client := databrokerpb.NewDataBrokerServiceClient(cc)

	syncer := databrokerpb.NewSyncer(ctx, "databroker", &syncerHandler{
		client: client,
		src:    src,
	}, databrokerpb.WithTypeURL(grpcutil.GetTypeURL(new(configpb.Config))),
		databrokerpb.WithFastForward(),
		databrokerpb.WithSyncerTracerProvider(src.tracerProvider))
	go func() {
		log.Ctx(ctx).Debug().
			Str("outbound-port", cfg.OutboundPort).
			Msg("config: starting databroker config source syncer")
		_ = syncer.Run(ctx)
	}()
}

type syncerHandler struct {
	src    *ConfigSource
	client databrokerpb.DataBrokerServiceClient
}

func (s *syncerHandler) GetDataBrokerServiceClient() databrokerpb.DataBrokerServiceClient {
	return s.client
}

func (s *syncerHandler) ClearRecords(_ context.Context) {
	s.src.mu.Lock()
	s.src.dbConfigs = map[string]dbConfig{}
	s.src.mu.Unlock()
}

func (s *syncerHandler) UpdateRecords(ctx context.Context, _ uint64, records []*databrokerpb.Record) {
	if len(records) == 0 {
		return
	}

	s.src.mu.Lock()
	for _, record := range records {
		if record.GetDeletedAt() != nil {
			delete(s.src.dbConfigs, record.GetId())
			continue
		}

		var cfgpb configpb.Config
		err := record.GetData().UnmarshalTo(&cfgpb)
		if err != nil {
			log.Ctx(ctx).Error().Err(err).Msg("databroker: error decoding config")
			delete(s.src.dbConfigs, record.GetId())
			continue
		}

		s.src.dbConfigs[record.GetId()] = dbConfig{&cfgpb, record.Version}
	}
	s.src.mu.Unlock()

	s.src.rebuild(ctx, firstTime(false))
}
