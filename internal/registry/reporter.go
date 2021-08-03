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
func (r *Reporter) OnConfigChange(ctx context.Context, cfg *config.Config) {
	if r.cancel != nil {
		r.cancel()
	}

	services, err := getReportedServices(cfg)
	if err != nil {
		log.Warn(ctx).Err(err).Msg("metrics announce to service registry is disabled")
	}

	sharedKey, err := cfg.Options.GetSharedKey()
	if err != nil {
		log.Error(ctx).Err(err).Msg("decoding shared key")
		return
	}

	urls, err := cfg.Options.GetDataBrokerURLs()
	if err != nil {
		log.Error(ctx).Err(err).Msg("invalid databroker urls")
		return
	}

	registryConn, err := grpc.GetGRPCClientConn(ctx, "databroker", &grpc.Options{
		Addrs:                   urls,
		OverrideCertificateName: cfg.Options.OverrideCertificateName,
		CA:                      cfg.Options.CA,
		CAFile:                  cfg.Options.CAFile,
		RequestTimeout:          cfg.Options.GRPCClientTimeout,
		ClientDNSRoundRobin:     cfg.Options.GRPCClientDNSRoundRobin,
		WithInsecure:            cfg.Options.GetGRPCInsecure(),
		InstallationID:          cfg.Options.InstallationID,
		ServiceName:             cfg.Options.Services,
		SignedJWTKey:            sharedKey,
	})
	if err != nil {
		log.Error(ctx).Err(err).Msg("connecting to registry")
		return
	}

	if len(services) > 0 {
		ctx, cancel := context.WithCancel(context.TODO())
		go runReporter(ctx, pb.NewRegistryClient(registryConn), services)
		r.cancel = cancel
	}
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
	host, port, err := net.SplitHostPort(o.MetricsAddr)
	if err != nil {
		return nil, fmt.Errorf("invalid metrics address %q: %w", o.MetricsAddr, err)
	}
	if port == "" {
		return nil, fmt.Errorf("invalid metrics value %q: port is required", o.MetricsAddr)
	}
	if host == "" {
		if host, err = getHostOrIP(); err != nil {
			return nil, fmt.Errorf("could not guess hostname: %w", err)
		}
	}

	u := url.URL{
		Scheme: "http",
		Host:   net.JoinHostPort(host, port),
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
		return nil, fmt.Errorf("no metrics address provided")
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
			log.Info(ctx).Msg("service registry reporter stopping")
			return
		}
	}
}
