package registry

import (
	"context"
	"encoding/base64"
	"fmt"
	"net"
	"net/url"
	"os"
	"time"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/pkg/grpc"
	pb "github.com/pomerium/pomerium/pkg/grpc/registry"

	"github.com/cenkalti/backoff/v4"
)

// Reporter periodically submits a list of services available on this instance to the service registry
type Reporter struct {
	cancel func()
}

// OnConfigChange applies configuration changes to the reporter
func (r *Reporter) OnConfigChange(cfg *config.Config) {
	if r.cancel != nil {
		r.cancel()
	}

	services, err := getReportedServices(cfg)
	if err != nil {
		log.Error().Err(err).Msg("applying config")
		return
	}

	sharedKey, err := base64.StdEncoding.DecodeString(cfg.Options.SharedKey)
	if err != nil {
		log.Error().Err(err).Msg("decoding shared key")
		return
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
		log.Error().Err(err).Msg("connecting to registry")
		return
	}

	ctx, cancel := context.WithCancel(context.TODO())
	go runReporter(ctx, pb.NewRegistryClient(registryConn), services)
	r.cancel = cancel
}

func getReportedServices(cfg *config.Config) ([]*pb.Service, error) {
	mu, err := metricsURL(cfg.Options.MetricsAddr)
	if err != nil {
		return nil, err
	}

	return []*pb.Service{
		{Kind: pb.ServiceKind_PROMETHEUS_METRICS, Endpoint: mu.String()},
	}, nil
}

func metricsURL(addr string) (*url.URL, error) {
	if addr == "" {
		return nil, errNoMetricsAddr
	}

	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, fmt.Errorf("invalid metrics address: %w", err)
	}

	if port == "" {
		return nil, errNoMetricsPort
	}

	if host == "" {
		host, err = os.Hostname()
		if err != nil {
			return nil, fmt.Errorf("metrics address is missing hostname, error obtaining it from OS: %w", err)
		}
	}

	return &url.URL{
		// TODO: TLS selector https://github.com/pomerium/internal/issues/272
		Scheme: "http",
		Path:   defaultMetricsPath,
		Host:   net.JoinHostPort(host, port),
	}, nil
}

func runReporter(
	ctx context.Context,
	client pb.RegistryClient,
	services []*pb.Service,
) {
	backoff := backoff.NewExponentialBackOff()
	backoff.MaxElapsedTime = 0

	req := &pb.RegisterRequest{Services: services}
	after := minTTL
	for {
		select {
		case <-time.After(after):
			resp, err := client.Report(ctx, req)
			if err != nil {
				log.Ctx(ctx).Error().Err(err).Msg("grpc.service_registry.Report")
				after = backoff.NextBackOff()
				continue
			}
			after = resp.CallBackAfter.AsDuration()
			backoff.Reset()
		case <-ctx.Done():
			log.Info().Msg("service registry reporter stopping")
			return
		}
	}
}
