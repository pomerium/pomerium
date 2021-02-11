package databroker

import (
	"context"
	"encoding/base64"
	"sync"

	"github.com/golang/protobuf/ptypes"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/hashutil"
	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/internal/telemetry/trace"
	"github.com/pomerium/pomerium/pkg/grpc"
	configpb "github.com/pomerium/pomerium/pkg/grpc/config"
	"github.com/pomerium/pomerium/pkg/grpc/databroker"
)

var configTypeURL string

func init() {
	any, _ := ptypes.MarshalAny(new(configpb.Config))
	configTypeURL = any.GetTypeUrl()
}

// ConfigSource provides a new Config source that decorates an underlying config with
// configuration derived from the data broker.
type ConfigSource struct {
	mu               sync.RWMutex
	computedConfig   *config.Config
	underlyingConfig *config.Config
	dbConfigs        map[string]*configpb.Config
	updaterHash      uint64
	cancel           func()

	config.ChangeDispatcher
}

// NewConfigSource creates a new ConfigSource.
func NewConfigSource(underlying config.Source, listeners ...config.ChangeListener) *ConfigSource {
	src := &ConfigSource{
		dbConfigs: map[string]*configpb.Config{},
	}
	for _, li := range listeners {
		src.OnConfigChange(li)
	}
	underlying.OnConfigChange(func(cfg *config.Config) {
		src.mu.Lock()
		src.underlyingConfig = cfg.Clone()
		src.mu.Unlock()

		src.rebuild(false)
	})
	src.underlyingConfig = underlying.GetConfig()
	src.rebuild(true)
	return src
}

// GetConfig gets the current config.
func (src *ConfigSource) GetConfig() *config.Config {
	src.mu.RLock()
	defer src.mu.RUnlock()

	return src.computedConfig
}

func (src *ConfigSource) rebuild(firstTime bool) {
	_, span := trace.StartSpan(context.Background(), "databroker.config_source.rebuild")
	defer span.End()

	src.mu.Lock()
	defer src.mu.Unlock()

	cfg := src.underlyingConfig.Clone()

	// start the updater
	src.runUpdater(cfg)

	seen := map[uint64]struct{}{}
	for _, policy := range cfg.Options.GetAllPolicies() {
		id, err := policy.RouteID()
		if err != nil {
			log.Warn().Err(err).
				Str("policy", policy.String()).
				Msg("databroker: invalid policy config, ignoring")
			return
		}
		seen[id] = struct{}{}
	}

	var additionalPolicies []config.Policy

	// add all the config policies to the list
	for _, cfgpb := range src.dbConfigs {
		cfg.Options.ApplySettings(cfgpb.Settings)

		err := cfg.Options.Validate()
		if err != nil {
			log.Warn().Err(err).Msg("databroker: invalid config detected, ignoring")
			return
		}

		for _, routepb := range cfgpb.GetRoutes() {
			policy, err := config.NewPolicyFromProto(routepb)
			if err != nil {
				log.Warn().Err(err).Msg("databroker: error converting protobuf into policy")
				continue
			}

			err = policy.Validate()
			if err != nil {
				log.Warn().Err(err).
					Str("policy", policy.String()).
					Msg("databroker: invalid policy, ignoring")
				continue
			}

			routeID, err := policy.RouteID()
			if err != nil {
				log.Warn().Err(err).
					Str("policy", policy.String()).
					Msg("databroker: cannot establish policy route ID, ignoring")
				continue
			}

			if _, ok := seen[routeID]; ok {
				log.Warn().Err(err).
					Str("policy", policy.String()).
					Msg("databroker: duplicate policy detected, ignoring")
				continue
			}
			seen[routeID] = struct{}{}

			additionalPolicies = append(additionalPolicies, *policy)
		}
	}

	// add the additional policies here since calling `Validate` will reset them.
	cfg.Options.AdditionalPolicies = append(cfg.Options.AdditionalPolicies, additionalPolicies...)

	src.computedConfig = cfg
	if !firstTime {
		src.Trigger(cfg)
	}
}

func (src *ConfigSource) runUpdater(cfg *config.Config) {
	sharedKey, _ := base64.StdEncoding.DecodeString(cfg.Options.SharedKey)
	connectionOptions := &grpc.Options{
		Addr:                    cfg.Options.DataBrokerURL,
		OverrideCertificateName: cfg.Options.OverrideCertificateName,
		CA:                      cfg.Options.CA,
		CAFile:                  cfg.Options.CAFile,
		RequestTimeout:          cfg.Options.GRPCClientTimeout,
		ClientDNSRoundRobin:     cfg.Options.GRPCClientDNSRoundRobin,
		WithInsecure:            cfg.Options.GRPCInsecure,
		ServiceName:             cfg.Options.Services,
		SignedJWTKey:            sharedKey,
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

	cc, err := grpc.NewGRPCClientConn(connectionOptions)
	if err != nil {
		log.Error().Err(err).Msg("databroker: failed to create gRPC connection to data broker")
		return
	}

	client := databroker.NewDataBrokerServiceClient(cc)

	ctx := context.Background()
	ctx, src.cancel = context.WithCancel(ctx)

	syncer := databroker.NewSyncer(&syncerHandler{
		client: client,
		src:    src,
	})
	go func() { _ = syncer.Run(ctx) }()
}

type syncerHandler struct {
	src    *ConfigSource
	client databroker.DataBrokerServiceClient
}

func (s *syncerHandler) GetDataBrokerServiceClient() databroker.DataBrokerServiceClient {
	return s.client
}

func (s *syncerHandler) ClearRecords(ctx context.Context) {
	s.src.mu.Lock()
	s.src.dbConfigs = map[string]*configpb.Config{}
	s.src.mu.Unlock()
}

func (s *syncerHandler) UpdateRecords(ctx context.Context, records []*databroker.Record) {
	s.src.mu.Lock()
	for _, record := range records {
		if record.GetDeletedAt() != nil {
			delete(s.src.dbConfigs, record.GetId())
			continue
		}

		var cfgpb configpb.Config
		err := ptypes.UnmarshalAny(record.GetData(), &cfgpb)
		if err != nil {
			log.Warn().Err(err).Msg("databroker: error decoding config")
			delete(s.src.dbConfigs, record.GetId())
			continue
		}

		s.src.dbConfigs[record.GetId()] = &cfgpb
	}
	s.src.mu.Unlock()

	s.src.rebuild(false)
}
