package controlplane

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sync/errgroup"
	"google.golang.org/grpc"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/pkg/cryptutil"
	databrokerpb "github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/grpc/events"
)

type mockDataBrokerServer struct {
	databrokerpb.DataBrokerServiceServer
	put        func(context.Context, *databrokerpb.PutRequest) (*databrokerpb.PutResponse, error)
	setOptions func(context.Context, *databrokerpb.SetOptionsRequest) (*databrokerpb.SetOptionsResponse, error)
}

func (mock *mockDataBrokerServer) Put(ctx context.Context, req *databrokerpb.PutRequest) (*databrokerpb.PutResponse, error) {
	return mock.put(ctx, req)
}

func (mock *mockDataBrokerServer) SetOptions(ctx context.Context, req *databrokerpb.SetOptionsRequest) (*databrokerpb.SetOptionsResponse, error) {
	return mock.setOptions(ctx, req)
}

func TestEvents(t *testing.T) {
	t.Run("passes events", func(t *testing.T) {
		srv := &Server{envoyConfigurationEvents: make(chan *events.EnvoyConfigurationEvent, 1)}
		srv.handleEnvoyConfigurationEvent(new(events.EnvoyConfigurationEvent))
		evt := <-srv.envoyConfigurationEvents
		assert.NotNil(t, evt)
	})
	t.Run("receives events", func(t *testing.T) {
		ctx := context.Background()

		srv := &Server{
			envoyConfigurationEvents: make(chan *events.EnvoyConfigurationEvent, 1),
		}
		srv.currentConfig.Store(versionedConfig{
			Config: &config.Config{
				Options: &config.Options{},
			},
		})

		ctx, cancel := context.WithCancel(ctx)
		eg, ctx := errgroup.WithContext(ctx)
		eg.Go(func() error {
			return srv.runEnvoyConfigurationEventHandler(ctx)
		})
		srv.envoyConfigurationEvents <- new(events.EnvoyConfigurationEvent)
		cancel()
		assert.Equal(t, context.Canceled, eg.Wait())
	})
	t.Run("saves events", func(t *testing.T) {
		ctx := context.Background()
		ctx, cancel := context.WithCancel(ctx)
		defer cancel()
		ctx, clearTimeout := context.WithTimeout(ctx, time.Second*5)
		defer clearTimeout()

		li, err := net.Listen("tcp", "127.0.0.1:0")
		require.NoError(t, err)
		defer li.Close()

		var putRequest *databrokerpb.PutRequest
		var setOptionsRequest *databrokerpb.SetOptionsRequest

		grpcSrv := grpc.NewServer()
		databrokerpb.RegisterDataBrokerServiceServer(grpcSrv, &mockDataBrokerServer{
			put: func(ctx context.Context, req *databrokerpb.PutRequest) (*databrokerpb.PutResponse, error) {
				putRequest = req
				return new(databrokerpb.PutResponse), nil
			},
			setOptions: func(ctx context.Context, req *databrokerpb.SetOptionsRequest) (*databrokerpb.SetOptionsResponse, error) {
				setOptionsRequest = req
				return new(databrokerpb.SetOptionsResponse), nil
			},
		})

		eg, ctx := errgroup.WithContext(ctx)
		eg.Go(func() error {
			<-ctx.Done()
			grpcSrv.Stop()
			return nil
		})
		eg.Go(func() error {
			return grpcSrv.Serve(li)
		})
		eg.Go(func() error {
			defer cancel()

			srv := &Server{}
			srv.currentConfig.Store(versionedConfig{
				Config: &config.Config{
					Options: &config.Options{
						SharedKey:           cryptutil.NewBase64Key(),
						DataBrokerURLString: "http://" + li.Addr().String(),
						GRPCInsecure:        true,
					},
				},
			})
			err := srv.storeEnvoyConfigurationEvent(ctx, new(events.EnvoyConfigurationEvent))
			assert.NoError(t, err)
			return err
		})
		_ = eg.Wait()

		assert.Equal(t, uint64(maxEnvoyConfigurationEvents), setOptionsRequest.GetOptions().GetCapacity())
		assert.Equal(t, "type.googleapis.com/pomerium.events.EnvoyConfigurationEvent", putRequest.GetRecord().GetType())
	})
}
