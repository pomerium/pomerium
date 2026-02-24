package databroker

import (
	"context"
	"fmt"
	"iter"
	"maps"
	"slices"
	"sync"
	"time"

	"go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc"
	oteltrace "go.opentelemetry.io/otel/trace"
	"golang.org/x/sync/errgroup"
	googlegrpc "google.golang.org/grpc"
	"google.golang.org/protobuf/proto"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/errgrouputil"
	"github.com/pomerium/pomerium/internal/hashutil"
	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/internal/telemetry/metrics"
	"github.com/pomerium/pomerium/internal/version"
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
	// index of all Config databroker records
	dbConfigs map[string]dbConfig
	// index of all applicable VersionedConfig databroker records
	dbVersionedConfigs   map[string]dbConfig
	bundle               *ConfigBundle
	bundleSnapshot       dbConfig
	bundleKeyPairsReady  bool
	bundlePoliciesReady  bool
	bundleRoutesReady    bool
	bundleSettingsReady  bool
	standardConfigReady  bool
	versionedConfigReady bool
	updaterHash          uint64
	cancel               func()
	enableValidation     bool
	tracerProvider       oteltrace.TracerProvider

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
		dbVersionedConfigs:     map[string]dbConfig{},
		bundle:                 NewConfigBundle(),
		outboundGRPCConnection: new(grpc.CachedOutboundGRPClientConn),
	}
	for _, li := range listeners {
		src.OnConfigChange(ctx, li)
	}
	underlying.OnConfigChange(ctx, func(ctx context.Context, cfg *config.Config) {
		src.mu.Lock()
		src.underlyingConfig = cfg.Clone()
		src.mu.Unlock()

		src.rebuild(ctx)
	})
	src.underlyingConfig = underlying.GetConfig()
	src.rebuild(ctx)
	return src
}

// GetConfig gets the current config.
func (src *ConfigSource) GetConfig() *config.Config {
	src.mu.RLock()
	defer src.mu.RUnlock()

	return src.computedConfig
}

func (src *ConfigSource) rebuild(ctx context.Context) {
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
		health.ReportError(health.DatabrokerBuildConfig, err)
		log.Ctx(ctx).Error().Err(err).Msg("databroker: failed to build new config")
		return
	}
	health.ReportRunning(health.DatabrokerBuildConfig)
	log.Ctx(ctx).Debug().Str("elapsed", time.Since(now).String()).Msg("databroker: built new config")

	src.computedConfig = cfg
	if src.standardConfigReady {
		src.Trigger(ctx, cfg)
	}

	metrics.SetConfigInfo(ctx, cfg.Options.Services, "databroker", cfg.Checksum(), true)
}

// allDBConfigsLocked returns an iterator over the union of values in dbConfigs
// and dbVersionedConfigs, in an unspecified order. The mutex must be held.
func (src *ConfigSource) allDBConfigsLocked() iter.Seq[*configpb.Config] {
	return func(yield func(*configpb.Config) bool) {
		if src.standardConfigReady {
			for _, c := range src.dbConfigs {
				if !yield(c.Config) {
					return
				}
			}
		}
		if src.versionedConfigReady {
			for _, c := range src.dbVersionedConfigs {
				if !yield(c.Config) {
					return
				}
			}
		}
		if src.bundleKeyPairsReady && src.bundlePoliciesReady && src.bundleRoutesReady && src.bundleSettingsReady {
			if !yield(src.bundleSnapshot.Config) {
				return
			}
		}
	}
}

// allSortedDBConfigsLocked returns an iterator that first yields the values of
// dbConfigs (sorted by key) and then the values of dbVersionedConfigs (again
// sorted by key). The mutex must be held.
func (src *ConfigSource) allSortedDBConfigsLocked() iter.Seq[*configpb.Config] {
	ids := slices.Sorted(maps.Keys(src.dbConfigs))
	idsVersioned := slices.Sorted(maps.Keys(src.dbVersionedConfigs))
	return func(yield func(*configpb.Config) bool) {
		if src.standardConfigReady {
			for _, id := range ids {
				if !yield(src.dbConfigs[id].Config) {
					return
				}
			}
		}
		if src.versionedConfigReady {
			for _, id := range idsVersioned {
				if !yield(src.dbVersionedConfigs[id].Config) {
					return
				}
			}
		}
		if src.bundleKeyPairsReady && src.bundlePoliciesReady && src.bundleRoutesReady && src.bundleSettingsReady {
			if !yield(src.bundleSnapshot.Config) {
				return
			}
		}
	}
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
	for cfgpb := range src.allDBConfigsLocked() {
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
	var certsIndex *cryptutil.CertificatesIndex
	if src.enableValidation {
		certsIndex = cryptutil.NewCertificatesIndex()
		for _, cert := range cfg.Options.GetX509Certificates() {
			certsIndex.Add(cert)
		}
	}

	for cfgpb := range src.allSortedDBConfigsLocked() {
		if ctx.Err() != nil {
			return
		}
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

	configSyncer := databrokerpb.NewSyncer(ctx, "databroker", &configSyncerHandler{
		client: client,
		src:    src,
	}, databrokerpb.WithTypeURL(grpcutil.GetTypeURL(new(configpb.Config))),
		databrokerpb.WithFastForward(),
		databrokerpb.WithSyncerTracerProvider(src.tracerProvider))
	go configSyncer.Run(ctx) //nolint:errcheck

	versionedConfigSyncer := databrokerpb.NewSyncer(ctx, "databroker", &versionedConfigSyncerHandler{
		client: client,
		src:    src,
	}, databrokerpb.WithTypeURL(grpcutil.GetTypeURL(new(configpb.VersionedConfig))),
		databrokerpb.WithFastForward(),
		databrokerpb.WithSyncerTracerProvider(src.tracerProvider))
	go versionedConfigSyncer.Run(ctx) //nolint:errcheck

	go databrokerpb.NewSyncer(ctx, "databroker",
		newEntityConfigSyncerHandler(src, client, src.bundle.KeyPairs, &src.bundleKeyPairsReady),
		databrokerpb.WithTypeURL(grpcutil.GetTypeURL(new(configpb.KeyPair))),
		databrokerpb.WithSyncerTracerProvider(src.tracerProvider)).Run(ctx) //nolint:errcheck
	go databrokerpb.NewSyncer(ctx, "databroker",
		newEntityConfigSyncerHandler(src, client, src.bundle.Policies, &src.bundlePoliciesReady),
		databrokerpb.WithTypeURL(grpcutil.GetTypeURL(new(configpb.Policy))),
		databrokerpb.WithSyncerTracerProvider(src.tracerProvider)).Run(ctx) //nolint:errcheck
	go databrokerpb.NewSyncer(ctx, "databroker",
		newEntityConfigSyncerHandler(src, client, src.bundle.Routes, &src.bundleRoutesReady),
		databrokerpb.WithTypeURL(grpcutil.GetTypeURL(new(configpb.Route))),
		databrokerpb.WithSyncerTracerProvider(src.tracerProvider)).Run(ctx) //nolint:errcheck
	go databrokerpb.NewSyncer(ctx, "databroker",
		newEntityConfigSyncerHandler(src, client, src.bundle.Settings, &src.bundleSettingsReady),
		databrokerpb.WithTypeURL(grpcutil.GetTypeURL(new(configpb.Settings))),
		databrokerpb.WithSyncerTracerProvider(src.tracerProvider)).Run(ctx) //nolint:errcheck

	log.Ctx(ctx).Debug().
		Str("outbound-port", cfg.OutboundPort).
		Msg("config: starting databroker config source syncer")
}

// configSyncerHandler manages updates to Config records.
type configSyncerHandler struct {
	src    *ConfigSource
	client databrokerpb.DataBrokerServiceClient
}

func (s *configSyncerHandler) GetDataBrokerServiceClient() databrokerpb.DataBrokerServiceClient {
	return s.client
}

func (s *configSyncerHandler) ClearRecords(_ context.Context) {
	s.src.mu.Lock()
	s.src.dbConfigs = map[string]dbConfig{}
	s.src.mu.Unlock()
}

func (s *configSyncerHandler) UpdateRecords(ctx context.Context, _ uint64, records []*databrokerpb.Record) {
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
	s.src.standardConfigReady = true
	s.src.mu.Unlock()

	s.src.rebuild(ctx)
}

// versionedConfigSyncerHandler manages updates to VersionedConfig records.
type versionedConfigSyncerHandler struct {
	src    *ConfigSource
	client databrokerpb.DataBrokerServiceClient
}

func (s *versionedConfigSyncerHandler) GetDataBrokerServiceClient() databrokerpb.DataBrokerServiceClient {
	return s.client
}

func (s *versionedConfigSyncerHandler) ClearRecords(_ context.Context) {
	s.src.mu.Lock()
	s.src.dbVersionedConfigs = map[string]dbConfig{}
	s.src.mu.Unlock()
}

func (s *versionedConfigSyncerHandler) UpdateRecords(ctx context.Context, _ uint64, records []*databrokerpb.Record) {
	versions := version.Components()
	versions[""] = version.Version

	s.src.mu.Lock()
	for _, record := range records {
		if record.GetDeletedAt() != nil {
			delete(s.src.dbVersionedConfigs, record.GetId())
			continue
		}

		var cfgpb configpb.VersionedConfig
		err := record.GetData().UnmarshalTo(&cfgpb)
		if err != nil {
			log.Ctx(ctx).Error().Err(err).Msg("databroker: error decoding config")
			delete(s.src.dbVersionedConfigs, record.GetId())
			continue
		}

		if cfgpb.IsApplicable(versions) {
			s.src.dbVersionedConfigs[record.GetId()] = dbConfig{cfgpb.Config, record.Version}
		} else {
			log.Ctx(ctx).Debug().
				Str("id", record.Id).
				Str("name", cfgpb.Config.GetName()).
				Msg("databroker: ignoring VersionedConfig record")
		}
	}
	s.src.versionedConfigReady = true
	s.src.mu.Unlock()

	s.src.rebuild(ctx)
}

type entityConfigSyncerHandler[T any, TMsg interface {
	*T
	proto.Message
}] struct {
	src      *ConfigSource
	client   databrokerpb.DataBrokerServiceClient
	entities map[string]TMsg
	ready    *bool
}

func newEntityConfigSyncerHandler[T any, TMsg interface {
	*T
	proto.Message
}](src *ConfigSource, client databrokerpb.DataBrokerServiceClient, entities map[string]TMsg, ready *bool) *entityConfigSyncerHandler[T, TMsg] {
	return &entityConfigSyncerHandler[T, TMsg]{
		src:      src,
		client:   client,
		entities: entities,
		ready:    ready,
	}
}

func (h *entityConfigSyncerHandler[T, TMsg]) GetDataBrokerServiceClient() databrokerpb.DataBrokerServiceClient {
	return h.client
}

func (h *entityConfigSyncerHandler[T, TMsg]) ClearRecords(_ context.Context) {
	h.src.mu.Lock()
	clear(h.entities)
	h.src.mu.Unlock()
}

func (h *entityConfigSyncerHandler[T, TMsg]) UpdateRecords(ctx context.Context, _ uint64, records []*databrokerpb.Record) {
	h.src.mu.Lock()
	for _, record := range records {
		h.src.bundleSnapshot.version = max(h.src.bundleSnapshot.version, record.Version)

		if record.GetDeletedAt() != nil {
			delete(h.entities, record.GetId())
			continue
		}

		msg := TMsg(new(T))
		err := record.GetData().UnmarshalTo(msg)
		if err != nil {
			log.Ctx(ctx).Error().Err(err).Msg("databroker: error decoding entity")
			delete(h.entities, record.GetId())
			continue
		}

		h.entities[record.GetId()] = msg
	}
	*h.ready = true
	h.src.bundleSnapshot.Config = h.src.bundle.Snapshot("bundle")
	h.src.mu.Unlock()

	h.src.rebuild(ctx)
}
