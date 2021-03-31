package authorize

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/grpc/session"
	"github.com/pomerium/pomerium/pkg/grpcutil"
)

func TestAuthorize_waitForRecordSync(t *testing.T) {
	ctx, clearTimeout := context.WithTimeout(context.Background(), time.Second*30)
	defer clearTimeout()

	o := &config.Options{
		AuthenticateURLString: "https://authN.example.com",
		DataBrokerURLString:   "https://databroker.example.com",
		SharedKey:             "gXK6ggrlIW2HyKyUF9rUO4azrDgxhDPWqw9y+lJU7B8=",
		Policies:              testPolicies(t),
	}
	t.Run("skip if exists", func(t *testing.T) {
		a, err := New(&config.Config{Options: o})
		require.NoError(t, err)

		a.store.UpdateRecord(0, newRecord(&session.Session{
			Id: "SESSION_ID",
		}))
		a.state.Load().dataBrokerClient = mockDataBrokerServiceClient{
			get: func(ctx context.Context, in *databroker.GetRequest, opts ...grpc.CallOption) (*databroker.GetResponse, error) {
				panic("should never be called")
			},
		}
		a.waitForRecordSync(ctx, grpcutil.GetTypeURL(new(session.Session)), "SESSION_ID")
	})
	t.Run("skip if not found", func(t *testing.T) {
		a, err := New(&config.Config{Options: o})
		require.NoError(t, err)

		callCount := 0
		a.state.Load().dataBrokerClient = mockDataBrokerServiceClient{
			get: func(ctx context.Context, in *databroker.GetRequest, opts ...grpc.CallOption) (*databroker.GetResponse, error) {
				callCount++
				return nil, status.Error(codes.NotFound, "not found")
			},
		}
		a.waitForRecordSync(ctx, grpcutil.GetTypeURL(new(session.Session)), "SESSION_ID")
		assert.Equal(t, 1, callCount, "should be called once")
	})
	t.Run("poll", func(t *testing.T) {
		a, err := New(&config.Config{Options: o})
		require.NoError(t, err)

		callCount := 0
		a.state.Load().dataBrokerClient = mockDataBrokerServiceClient{
			get: func(ctx context.Context, in *databroker.GetRequest, opts ...grpc.CallOption) (*databroker.GetResponse, error) {
				callCount++
				switch callCount {
				case 1:
					s := &session.Session{Id: "SESSION_ID"}
					a.store.UpdateRecord(0, newRecord(s))
					return &databroker.GetResponse{Record: newRecord(s)}, nil
				default:
					panic("should never be called")
				}
			},
		}
		a.waitForRecordSync(ctx, grpcutil.GetTypeURL(new(session.Session)), "SESSION_ID")
	})
	t.Run("timeout", func(t *testing.T) {
		a, err := New(&config.Config{Options: o})
		require.NoError(t, err)

		tctx, clearTimeout := context.WithTimeout(ctx, time.Millisecond*100)
		defer clearTimeout()

		callCount := 0
		a.state.Load().dataBrokerClient = mockDataBrokerServiceClient{
			get: func(ctx context.Context, in *databroker.GetRequest, opts ...grpc.CallOption) (*databroker.GetResponse, error) {
				callCount++
				s := &session.Session{Id: "SESSION_ID"}
				return &databroker.GetResponse{Record: newRecord(s)}, nil
			},
		}
		a.waitForRecordSync(tctx, grpcutil.GetTypeURL(new(session.Session)), "SESSION_ID")
		assert.Greater(t, callCount, 5) // should be ~ 20, but allow for non-determinism
	})
}

type storableMessage interface {
	proto.Message
	GetId() string
}

func newRecord(msg storableMessage) *databroker.Record {
	any, err := anypb.New(msg)
	if err != nil {
		panic(err)
	}
	return &databroker.Record{
		Version: 1,
		Type:    any.GetTypeUrl(),
		Id:      msg.GetId(),
		Data:    any,
	}
}
