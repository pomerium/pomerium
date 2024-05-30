// Package zero contains the pomerium zero configuration API client
package zero

import (
	"context"
	"fmt"
	"time"

	"go.opentelemetry.io/otel/sdk/metric/metricdata"
	"google.golang.org/grpc"
	"google.golang.org/grpc/keepalive"

	"github.com/pomerium/pomerium/internal/zero/apierror"
	connect_mux "github.com/pomerium/pomerium/internal/zero/connect-mux"
	"github.com/pomerium/pomerium/internal/zero/grpcconn"
	"github.com/pomerium/pomerium/internal/zero/healthcheck"
	"github.com/pomerium/pomerium/internal/zero/reporter"
	token_api "github.com/pomerium/pomerium/internal/zero/token"
	"github.com/pomerium/pomerium/pkg/fanout"
	cluster_api "github.com/pomerium/pomerium/pkg/zero/cluster"
	connect_api "github.com/pomerium/pomerium/pkg/zero/connect"
)

// API is a Pomerium Zero Cluster API client
type API struct {
	cfg              *config
	cluster          cluster_api.ClientWithResponsesInterface
	telemetryConn    *grpc.ClientConn
	reporter         *reporter.Reporter
	mux              *connect_mux.Mux
	downloadURLCache *cluster_api.URLCache
	tokenFn          func(ctx context.Context, ttl time.Duration) (string, error)
}

const (
	// access tokens are only good for an hour,
	// and they define the maximum connection time,
	// so we want it to be as close to the max as possible for the streaming gRPC connection
	minConnectTokenTTL = time.Minute * 55

	minTelemetryTokenTTL = time.Minute * 5
)

// see https://github.com/pomerium/pomerium-zero/issues/1711
var connectClientKeepaliveParams = keepalive.ClientParameters{
	Time:                time.Minute, // send pings every minute
	Timeout:             time.Minute, // wait 1 minute for ping ack
	PermitWithoutStream: false,
}

// WatchOption defines which events to watch for
type WatchOption = connect_mux.WatchOption

// NewAPI creates a new API client
func NewAPI(ctx context.Context, opts ...Option) (*API, error) {
	cfg, err := newConfig(opts...)
	if err != nil {
		return nil, err
	}

	fetcher, err := cluster_api.NewTokenFetcher(cfg.clusterAPIEndpoint,
		cluster_api.WithHTTPClient(cfg.httpClient),
	)
	if err != nil {
		return nil, fmt.Errorf("error creating token fetcher: %w", err)
	}

	tokenCache := token_api.NewCache(fetcher, cfg.apiToken)

	clusterClient, err := cluster_api.NewAuthorizedClient(cfg.clusterAPIEndpoint, tokenCache.GetToken, cfg.httpClient)
	if err != nil {
		return nil, fmt.Errorf("error creating cluster client: %w", err)
	}

	connectGRPCConn, err := grpcconn.New(ctx, cfg.connectAPIEndpoint, func(ctx context.Context) (string, error) {
		return tokenCache.GetToken(ctx, minConnectTokenTTL)
	}, grpc.WithKeepaliveParams(connectClientKeepaliveParams))
	if err != nil {
		return nil, fmt.Errorf("error creating connect grpc client: %w", err)
	}

	telemetryGRPCConn, err := grpcconn.New(ctx, cfg.otelEndpoint, func(ctx context.Context) (string, error) {
		return tokenCache.GetToken(ctx, minTelemetryTokenTTL)
	})
	if err != nil {
		return nil, fmt.Errorf("error creating OTEL exporter grpc client: %w", err)
	}

	reporter, err := reporter.New(ctx, telemetryGRPCConn)
	if err != nil {
		return nil, fmt.Errorf("error creating metrics reporter: %w", err)
	}

	return &API{
		cfg:              cfg,
		cluster:          clusterClient,
		mux:              connect_mux.New(connect_api.NewConnectClient(connectGRPCConn)),
		telemetryConn:    telemetryGRPCConn,
		reporter:         reporter,
		downloadURLCache: cluster_api.NewURLCache(),
		tokenFn:          tokenCache.GetToken,
	}, nil
}

// ReportPeriodicMetrics runs periodic metrics collection and reporting to the cloud
func (api *API) ReportPeriodicMetrics(ctx context.Context, opts ...reporter.Option) error {
	return api.reporter.RunPeriodicMetricReporter(ctx, opts...)
}

func (api *API) ReportMetrics(ctx context.Context, metrics []metricdata.Metrics) error {
	return api.reporter.ReportMetrics(ctx, metrics)
}

// ReportHealthChecks runs health check reporting to the cloud
func (api *API) ReportHealthChecks(ctx context.Context) error {
	return healthcheck.NewReporter(api.telemetryConn).Run(ctx)
}

// Connect connects to the connect API and allows watching for changes
func (api *API) Connect(ctx context.Context, opts ...fanout.Option) error {
	return api.mux.Run(ctx, opts...)
}

// Watch dispatches API updates
func (api *API) Watch(ctx context.Context, opts ...WatchOption) error {
	return api.mux.Watch(ctx, opts...)
}

// GetClusterBootstrapConfig fetches the bootstrap configuration from the cluster API
func (api *API) GetClusterBootstrapConfig(ctx context.Context) (*cluster_api.BootstrapConfig, error) {
	return apierror.CheckResponse[cluster_api.BootstrapConfig](
		api.cluster.GetClusterBootstrapConfigWithResponse(ctx),
	)
}

// GetClusterResourceBundles fetches the resource bundles from the cluster API
func (api *API) GetClusterResourceBundles(ctx context.Context) (*cluster_api.GetBundlesResponse, error) {
	return apierror.CheckResponse[cluster_api.GetBundlesResponse](
		api.cluster.GetClusterResourceBundlesWithResponse(ctx),
	)
}
