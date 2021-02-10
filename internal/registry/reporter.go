package registry

import (
	"context"
	"encoding/base64"
	"fmt"
	"time"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/pkg/grpc"
	pb "github.com/pomerium/pomerium/pkg/grpc/registry"
)

type Reporter struct {
	cancel func()
}

func NewReporter(cfg *config.Config) (*Reporter, error) {
	return fromConfig(cfg)
}

func (r *Reporter) OnConfigChange(cfg *config.Config) {
	log.Info().Msg("registry reporter - on config change")
}

func fromConfig(cfg *config.Config) (*Reporter, error) {
	sharedKey, err := base64.StdEncoding.DecodeString(cfg.Options.SharedKey)
	if err != nil {
		return nil, fmt.Errorf("decoding shared key: %w", err)
	}

	registryConn, err := grpc.GetGRPCClientConn("databroker", &grpc.Options{
		Addr:                    cfg.Options.DataBrokerURL,
		OverrideCertificateName: cfg.Options.OverrideCertificateName,
		CA:                      cfg.Options.CA,
		CAFile:                  cfg.Options.CAFile,
		RequestTimeout:          cfg.Options.GRPCClientTimeout,
		ClientDNSRoundRobin:     cfg.Options.GRPCClientDNSRoundRobin,
		WithInsecure:            cfg.Options.GRPCInsecure,
		ServiceName:             cfg.Options.Services,
		SignedJWTKey:            sharedKey,
	})
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithCancel(context.TODO())
	go runReporter(ctx, pb.NewRegistryClient(registryConn),
		[]*pb.Service{{
			Endpoint: fmt.Sprintf("http://%s", cfg.Options.MetricsAddr),
			Kind:     pb.ServiceKind_PROMETHEUS_METRICS,
		}})

	return &Reporter{cancel: cancel}, nil
}

func runReporter(
	ctx context.Context,
	client pb.RegistryClient,
	services []*pb.Service,
) {
	req := &pb.RegisterRequest{Services: services}
	after := time.Duration(minTTL)
	for {
		select {
		case <-time.After(after):
			log.Info().Msg("grpc.service_registry.Report")
			resp, err := client.Report(ctx, req)
			if err != nil {
				log.Error().Err(err).Msg("grpc.service_registry.Report")
				continue
			}
			after = resp.CallBackAfter.AsDuration()
		case <-ctx.Done():
			log.Info().Msg("service registry reporter stopping")
			return
		}
	}
}
