package databroker_test

import (
	"context"
	"testing"
	"testing/synctest"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/volatiletech/null/v9"
	"go.opentelemetry.io/otel/trace/noop"
	"google.golang.org/protobuf/types/known/emptypb"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/databroker"
	databrokerpb "github.com/pomerium/pomerium/pkg/grpc/databroker"
)

type clusteredServerTestBackend struct {
	databroker.Server
	serverInfo func(context.Context, *emptypb.Empty) (*databrokerpb.ServerInfoResponse, error)
}

func (b clusteredServerTestBackend) OnConfigChange(_ context.Context, _ *config.Config) {
}

func (b clusteredServerTestBackend) ServerInfo(ctx context.Context, req *emptypb.Empty) (*databrokerpb.ServerInfoResponse, error) {
	return b.serverInfo(ctx, req)
}

func (b clusteredServerTestBackend) Stop() {
}

func TestClusteredServer(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		cfg := config.New(config.NewDefaultOptions())
		cfg.Options.DataBroker.ClusterNodeID = null.StringFrom("node-1")

		serverInfoStarted := make(chan struct{})
		serverInfoFinished := make(chan struct{})
		configChanged := make(chan struct{})

		local := &clusteredServerTestBackend{
			serverInfo: func(ctx context.Context, _ *emptypb.Empty) (*databrokerpb.ServerInfoResponse, error) {
				close(serverInfoStarted)
				<-ctx.Done()
				// keep running after cancellation, so the server change
				// has to wait for this call to finish
				time.Sleep(time.Second)
				close(serverInfoFinished)
				return &databrokerpb.ServerInfoResponse{}, nil
			},
		}
		clustered := databroker.NewClusteredServer(noop.NewTracerProvider(), local, cfg)
		defer clustered.Stop()

		go func() {
			defer close(configChanged)
			<-serverInfoStarted
			// change the config to force an update, this should cancel the context passed to server info
			cfg.Options.DataBroker.ClusterNodeID = null.StringFrom("node-2")
			clustered.OnConfigChange(t.Context(), cfg)

			// the update should not complete until in-flight calls have finished
			select {
			case <-serverInfoFinished:
			default:
				assert.Fail(t, "config change completed before in-flight server info finished")
			}
		}()

		res, err := clustered.ServerInfo(t.Context(), new(emptypb.Empty))
		assert.NoError(t, err)
		assert.NotNil(t, res)
		<-configChanged
	})
}
