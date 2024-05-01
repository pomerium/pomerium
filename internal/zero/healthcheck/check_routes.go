package healthcheck

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/http"
	"slices"
	"time"

	"github.com/go-jose/go-jose/v3"
	"golang.org/x/exp/maps"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/internal/urlutil"
	"github.com/pomerium/pomerium/pkg/cryptutil"
	configpb "github.com/pomerium/pomerium/pkg/grpc/config"
	"github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/health"
	"github.com/pomerium/pomerium/pkg/protoutil"
	clusterping "github.com/pomerium/pomerium/pkg/zero/ping"
)

// CheckRoutes checks whether all routes that are referenced by this pomerium instance configuration are reachable
// it resolves the DNS entry and tries to access a pomerium jwks route
// we should hit ourselves and observe the same public key that we have in our configuration
// otherwise, something is misconfigured on the DNS level
func (c *checker) CheckRoutes(ctx context.Context) {
	err := checkRoutesReachable(ctx, c.bootstrap.GetConfig(), c.databrokerClient)
	if err != nil {
		log.Warn(ctx).Err(err).Msg("routes reachability check failed")
	}
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
	cfg *config.Config,
	databrokerClient databroker.DataBrokerServiceClient,
) error {
	key, err := getClusterPublicKey(cfg)
	if err != nil {
		return fmt.Errorf("error getting cluster public key: %w", err)
	}

	hosts, err := getRouteHosts(ctx, databrokerClient)
	if err != nil {
		return fmt.Errorf("error getting route hosts: %w", err)
	}
	slices.Sort(hosts)

	client := getPingHTTPClient()
	var errs []error
	for _, host := range hosts {
		err = clusterping.CheckKey(ctx, clusterping.GetJWKSURL(host), *key, client)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", host, err))
		}
	}

	if len(errs) == 0 {
		health.ReportOK(health.RoutesReachable)
	} else {
		health.ReportError(health.RoutesReachable, errors.Join(errs...))
	}

	return nil
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

func getRouteHosts(ctx context.Context, databrokerClient databroker.DataBrokerServiceClient) ([]string, error) {
	records, _, _, err := databroker.InitialSync(ctx, databrokerClient, &databroker.SyncLatestRequest{
		Type: protoutil.GetTypeURL(new(configpb.Config)),
	})
	if err != nil {
		return nil, fmt.Errorf("error during initial sync: %w", err)
	}

	hosts := make(map[string]struct{})
	for _, record := range records {
		var cfg configpb.Config
		if err := record.Data.UnmarshalTo(&cfg); err != nil {
			return nil, fmt.Errorf("error unmarshalling config: %w", err)
		}

		for _, route := range cfg.GetRoutes() {
			if route.GetTlsCustomCa() != "" {
				continue
			}
			u, err := urlutil.ParseAndValidateURL(route.GetFrom())
			if err != nil {
				continue
			}
			hosts[u.Host] = struct{}{}
		}
	}

	return maps.Keys(hosts), nil
}
