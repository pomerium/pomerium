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
	"google.golang.org/protobuf/proto"

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
	t.Parallel()

	t.Run("saves events", func(t *testing.T) {
		ctx := t.Context()
		ctx, cancel := context.WithCancel(ctx)
		defer cancel()
		ctx, clearTimeout := context.WithTimeout(ctx, time.Second*5)
		defer clearTimeout()

		li, err := net.Listen("tcp", "127.0.0.1:0")
		require.NoError(t, err)
		defer li.Close()
		_, outboundPort, _ := net.SplitHostPort(li.Addr().String())

		var putRequest *databrokerpb.PutRequest
		var setOptionsRequest *databrokerpb.SetOptionsRequest

		grpcSrv := grpc.NewServer()
		databrokerpb.RegisterDataBrokerServiceServer(grpcSrv, &mockDataBrokerServer{
			put: func(_ context.Context, req *databrokerpb.PutRequest) (*databrokerpb.PutResponse, error) {
				putRequest = req
				return new(databrokerpb.PutResponse), nil
			},
			setOptions: func(_ context.Context, req *databrokerpb.SetOptionsRequest) (*databrokerpb.SetOptionsResponse, error) {
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

			srv := &Server{
				haveSetCapacity: make(map[string]bool),
			}
			srv.currentConfig.Store(&config.Config{
				OutboundPort: outboundPort,
				Options: &config.Options{
					SharedKey:    cryptutil.NewBase64Key(),
					DataBroker:   config.DataBrokerOptions{ServiceURL: "http://" + li.Addr().String()},
					GRPCInsecure: proto.Bool(true),
				},
			})
			err := srv.storeEvent(ctx, new(events.LastError))
			assert.NoError(t, err)
			return err
		})
		_ = eg.Wait()

		assert.Equal(t, uint64(maxEvents), setOptionsRequest.GetOptions().GetCapacity())
		assert.Equal(t, "type.googleapis.com/pomerium.events.LastError", putRequest.GetRecord().GetType())
	})
}
