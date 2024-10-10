// Package zero contains the pomerium zero configuration API client
package zero

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"time"

	"github.com/klauspost/compress/zstd"
	"google.golang.org/grpc"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/protobuf/proto"

	"github.com/pomerium/pomerium/internal/zero/apierror"
	connect_mux "github.com/pomerium/pomerium/internal/zero/connect-mux"
	"github.com/pomerium/pomerium/internal/zero/grpcconn"
	token_api "github.com/pomerium/pomerium/internal/zero/token"
	"github.com/pomerium/pomerium/pkg/fanout"
	configpb "github.com/pomerium/pomerium/pkg/grpc/config"
	cluster_api "github.com/pomerium/pomerium/pkg/zero/cluster"
	connect_api "github.com/pomerium/pomerium/pkg/zero/connect"
)

// API is a Pomerium Zero Cluster API client
type API struct {
	cfg              *config
	cluster          cluster_api.ClientWithResponsesInterface
	telemetryConn    *grpc.ClientConn
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

	clusterClient, err := cluster_api.NewAuthorizedClient(cfg.clusterAPIEndpoint, tokenCache, cfg.httpClient)
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

	return &API{
		cfg:              cfg,
		cluster:          clusterClient,
		mux:              connect_mux.New(connect_api.NewConnectClient(connectGRPCConn)),
		telemetryConn:    telemetryGRPCConn,
		downloadURLCache: cluster_api.NewURLCache(),
		tokenFn:          tokenCache.GetToken,
	}, nil
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
	return apierror.CheckResponse(
		api.cluster.GetClusterBootstrapConfigWithResponse(ctx),
	)
}

// GetClusterResourceBundles fetches the resource bundles from the cluster API
func (api *API) GetClusterResourceBundles(ctx context.Context) (*cluster_api.GetBundlesResponse, error) {
	return apierror.CheckResponse(
		api.cluster.GetClusterResourceBundlesWithResponse(ctx),
	)
}

func (api *API) ImportConfig(ctx context.Context, cfg *configpb.Config, params *cluster_api.ImportConfigurationParams) (*cluster_api.ImportResponse, error) {
	data, err := proto.Marshal(cfg)
	if err != nil {
		return nil, err
	}
	var compressedData bytes.Buffer
	w, err := zstd.NewWriter(&compressedData, zstd.WithEncoderLevel(zstd.SpeedBestCompression))
	if err != nil {
		panic(fmt.Sprintf("bug: %v", err))
	}
	_, err = io.Copy(w, bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	if err := w.Close(); err != nil {
		return nil, err
	}
	return apierror.CheckResponse(api.cluster.ImportConfigurationWithBodyWithResponse(ctx,
		params,
		"application/octet-stream",
		&compressedData,
	))
}

func (api *API) GetTelemetryConn() *grpc.ClientConn {
	return api.telemetryConn
}

func (api *API) ReportUsage(ctx context.Context, req cluster_api.ReportUsageRequest) error {
	_, err := apierror.CheckResponse(
		api.cluster.ReportUsageWithResponse(ctx, req),
	)
	return err
}
