package databroker

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/cenkalti/backoff/v4"
	"github.com/golang/protobuf/ptypes"
	"github.com/mitchellh/hashstructure"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/pkg/grpc"
	configpb "github.com/pomerium/pomerium/pkg/grpc/config"
	"github.com/pomerium/pomerium/pkg/grpc/databroker"
)

var (
	configTypeURL string
)

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
	serverVersion    string
	recordVersion    string

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
	src.mu.Lock()
	defer src.mu.Unlock()

	cfg := src.underlyingConfig.Clone()

	// start the updater
	src.runUpdater(cfg)

	seen := map[uint64]struct{}{}
	for _, policy := range cfg.Options.Policies {
		seen[policy.RouteID()] = struct{}{}
	}

	// add all the config policies to the list
	for _, cfgpb := range src.dbConfigs {
		cfg.Options.ApplySettings(cfgpb.Settings)

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

			routeID := policy.RouteID()

			if _, ok := seen[routeID]; ok {
				log.Warn().Err(err).
					Str("policy", policy.String()).
					Msg("databroker: duplicate policy detected, ignoring")
				continue
			}
			seen[routeID] = struct{}{}

			cfg.Options.Policies = append(cfg.Options.Policies, *policy)
		}

		err := cfg.Options.Validate()
		if err != nil {
			log.Warn().Err(err).Msg("databroker: invalid config detected, ignoring")
			return
		}
	}

	src.computedConfig = cfg
	if !firstTime {
		src.Trigger(cfg)
	}
}

func (src *ConfigSource) runUpdater(cfg *config.Config) {
	connectionOptions := &grpc.Options{
		Addr:                    cfg.Options.DataBrokerURL,
		OverrideCertificateName: cfg.Options.OverrideCertificateName,
		CA:                      cfg.Options.CA,
		CAFile:                  cfg.Options.CAFile,
		RequestTimeout:          cfg.Options.GRPCClientTimeout,
		ClientDNSRoundRobin:     cfg.Options.GRPCClientDNSRoundRobin,
		WithInsecure:            cfg.Options.GRPCInsecure,
		ServiceName:             cfg.Options.Services,
	}
	h, err := hashstructure.Hash(connectionOptions, nil)
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

	go tryForever(ctx, func(onSuccess func()) error {
		src.mu.Lock()
		serverVersion, recordVersion := src.serverVersion, src.recordVersion
		src.mu.Unlock()

		stream, err := client.Sync(ctx, &databroker.SyncRequest{
			Type:          configTypeURL,
			ServerVersion: serverVersion,
			RecordVersion: recordVersion,
		})
		if err != nil {
			return err
		}

		for {
			res, err := stream.Recv()
			if err != nil {
				return err
			}
			onSuccess()

			if len(res.GetRecords()) > 0 {
				src.onSync(res.GetRecords())
				for _, record := range res.GetRecords() {
					recordVersion = record.GetVersion()
				}
			}

			src.mu.Lock()
			src.serverVersion, src.recordVersion = res.GetServerVersion(), recordVersion
			src.mu.Unlock()
		}
	})
}

func (src *ConfigSource) onSync(records []*databroker.Record) {
	src.mu.Lock()
	for _, record := range records {
		if record.GetDeletedAt() != nil {
			delete(src.dbConfigs, record.GetId())
			continue
		}

		var cfgpb configpb.Config
		err := ptypes.UnmarshalAny(record.GetData(), &cfgpb)
		if err != nil {
			log.Warn().Err(err).Msg("databroker: error decoding config")
			delete(src.dbConfigs, record.GetId())
			continue
		}

		src.dbConfigs[record.GetId()] = &cfgpb
	}
	src.mu.Unlock()

	src.rebuild(false)
}

func tryForever(ctx context.Context, callback func(onSuccess func()) error) {
	bo := backoff.NewExponentialBackOff()
	bo.MaxElapsedTime = 0
	for {
		err := callback(bo.Reset)
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return
		} else if err != nil {
			log.Warn().Err(err).Msg("sync error")
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(bo.NextBackOff()):
		}
	}
}
