package registry

import (
	"context"
	"encoding/base64"
	"fmt"
	"net"
	"net/url"
	"strings"
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
		log.Error().Err(err).Msg("service registry reporter")
		return
	}

	sharedKey, err := base64.StdEncoding.DecodeString(cfg.Options.SharedKey)
	if err != nil {
		log.Error().Err(err).Msg("decoding shared key")
		return
	}

	urls, err := cfg.Options.GetDataBrokerURLs()
	if err != nil {
		log.Error().Err(err).Msg("invalid databroker urls")
		return
	}

	registryConn, err := grpc.GetGRPCClientConn("databroker", &grpc.Options{
		Addrs:                   urls,
		OverrideCertificateName: cfg.Options.OverrideCertificateName,
		CA:                      cfg.Options.CA,
		CAFile:                  cfg.Options.CAFile,
		RequestTimeout:          cfg.Options.GRPCClientTimeout,
		ClientDNSRoundRobin:     cfg.Options.GRPCClientDNSRoundRobin,
		WithInsecure:            cfg.Options.GRPCInsecure,
		InstallationID:          cfg.Options.InstallationID,
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
	mu, err := metricsURL(*cfg.Options)
	if err != nil {
		return nil, err
	}

	return []*pb.Service{
		{Kind: pb.ServiceKind_PROMETHEUS_METRICS, Endpoint: mu.String()},
	}, nil
}

func metricsURL(o config.Options) (*url.URL, error) {
	u := url.URL{
		Scheme: "http",
		Host:   o.MetricsAddr,
		Path:   defaultMetricsPath,
	}

	if o.MetricsBasicAuth != "" {
		txt, err := base64.StdEncoding.DecodeString(o.MetricsBasicAuth)
		if err != nil {
			return nil, fmt.Errorf("metrics basic auth: %w", err)
		}
		parts := strings.SplitN(string(txt), ":", 2)
		if len(parts) != 2 {
			return nil, fmt.Errorf("expected username:password for basic auth")
		}
		u.User = url.UserPassword(parts[0], parts[1])
	}

	if o.MetricsCertificate != "" || o.MetricsCertificateFile != "" {
		u.Scheme = "https"
	}

	if o.MetricsAddr == "" {
		return nil, errNoMetricsAddr
	}

	host, port, err := net.SplitHostPort(o.MetricsAddr)
	if err != nil {
		return nil, fmt.Errorf("invalid metrics address: %w", err)
	}

	if port == "" {
		return nil, errNoMetricsPort
	}

	if host == "" {
		return nil, errNoMetricsHost
	}

	return &u, nil
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
