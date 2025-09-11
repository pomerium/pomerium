package healthcheck

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"maps"
	"net"
	"net/http"
	"slices"
	"time"

	"github.com/go-jose/go-jose/v3"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/urlutil"
	"github.com/pomerium/pomerium/pkg/cryptutil"
	configpb "github.com/pomerium/pomerium/pkg/grpc/config"
	"github.com/pomerium/pomerium/pkg/health"
	clusterping "github.com/pomerium/pomerium/pkg/zero/ping"
)

// CheckRoutes checks whether all routes that are referenced by this pomerium instance configuration are reachable
// it resolves the DNS entry and tries to access a pomerium jwks route
// we should hit ourselves and observe the same public key that we have in our configuration
// otherwise, something is misconfigured on the DNS level
func (c *Checker) CheckRoutes(ctx context.Context) error {
	key, err := getClusterPublicKey(c.bootstrap.GetConfig())
	if err != nil {
		health.ReportInternalError(health.ZeroRoutesReachable, err)
		return err
	}

	err = checkRoutesReachable(ctx, key, c.GetConfigs())
	if err == nil {
		health.ReportRunning(health.ZeroRoutesReachable)
	} else if ctx.Err() == nil {
		health.ReportError(health.ZeroRoutesReachable, err)
	}
	return err
}

const (
	connectionTimeout = time.Second * 30
)

func getPingHTTPClient() *http.Client {
	return &http.Client{
		Timeout: connectionTimeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return (&net.Dialer{
					Timeout: connectionTimeout,
				}).DialContext(ctx, network, addr)
			},
		},
	}
}

func checkRoutesReachable(
	ctx context.Context,
	key *jose.JSONWebKey,
	configs []*configpb.Config,
) error {
	hosts, err := getHosts(configs)
	if err != nil {
		return fmt.Errorf("error getting route hosts: %w", err)
	}

	client := getPingHTTPClient()
	var errs []error
	for _, host := range hosts {
		err = clusterping.CheckKey(ctx, clusterping.GetJWKSURL(host), *key, client)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", host, err))
		}
	}

	return errors.Join(errs...)
}

func getClusterPublicKey(cfg *config.Config) (*jose.JSONWebKey, error) {
	data, err := base64.StdEncoding.DecodeString(cfg.Options.SigningKey)
	if err != nil {
		return nil, fmt.Errorf("error decoding signing key: %w", err)
	}

	key, err := cryptutil.PublicJWKFromBytes(data)
	if err != nil {
		return nil, fmt.Errorf("error creating public jwk from bytes: %w", err)
	}

	return key, nil
}

func getHosts(configs []*configpb.Config) ([]string, error) {
	hosts := make(map[string]struct{})
	for _, cfg := range configs {
		for _, route := range cfg.GetRoutes() {
			if route.GetTlsCustomCa() != "" {
				continue
			}
			u, err := urlutil.ParseAndValidateURL(route.GetFrom())
			if err != nil {
				continue
			}
			if u.Scheme != "https" {
				// there's a complication with TCP+HTTPS routes as in general we may not know the host address for them
				// and we can't rely on the config's server address port part, as it may be different from actual externally reachable port
				continue
			}
			hosts[u.Host] = struct{}{}
		}
	}

	return slices.Sorted(maps.Keys(hosts)), nil
}
