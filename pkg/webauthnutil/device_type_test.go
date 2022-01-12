package webauthnutil

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/anypb"

	"github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/grpc/device"
)

func TestGetDeviceType(t *testing.T) {
	ctx := context.Background()

	t.Run("from databroker", func(t *testing.T) {
		client := &mockDataBrokerServiceClient{
			get: func(ctx context.Context, in *databroker.GetRequest, opts ...grpc.CallOption) (*databroker.GetResponse, error) {
				assert.Equal(t, "type.googleapis.com/pomerium.device.Type", in.GetType())
				assert.Equal(t, "any", in.GetId())
				any, _ := anypb.New(&device.Type{
					Id:   "any",
					Name: "Example",
				})
				return &databroker.GetResponse{
					Record: &databroker.Record{
						Type: in.GetType(),
						Id:   in.GetId(),
						Data: any,
					},
				}, nil
			},
		}
		deviceType := GetDeviceType(ctx, client, "any")
		assert.Equal(t, "Example", deviceType.GetName())
	})
	t.Run("default", func(t *testing.T) {
		client := &mockDataBrokerServiceClient{
			get: func(ctx context.Context, in *databroker.GetRequest, opts ...grpc.CallOption) (*databroker.GetResponse, error) {
				return nil, status.Error(codes.NotFound, "not found")
			},
		}
		deviceType := GetDeviceType(ctx, client, "any")
		assert.Equal(t, "Any", deviceType.GetName())
	})
}
