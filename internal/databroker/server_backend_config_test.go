package databroker_test

import (
	"testing"

	"connectrpc.com/connect"
	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/assert"
	"go.opentelemetry.io/otel/trace/noop"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/testing/protocmp"

	"github.com/pomerium/pomerium/internal/databroker"
	configpb "github.com/pomerium/pomerium/pkg/grpc/config"
)

func TestSettings(t *testing.T) {
	t.Parallel()

	srv := databroker.NewBackendServer(noop.NewTracerProvider())
	res1, err := srv.GetSettings(t.Context(), connect.NewRequest(&configpb.GetSettingsRequest{}))
	assert.NoError(t, err)
	assert.Equal(t, databroker.GlobalSettingsID, res1.Msg.GetSettings().GetId(),
		"should return an empty settings object if none is set")

	res2, err := srv.UpdateSettings(t.Context(), connect.NewRequest(&configpb.UpdateSettingsRequest{
		Settings: &configpb.Settings{
			LogLevel: proto.String("debug"),
		},
	}))
	assert.NoError(t, err)
	assert.NotNil(t, res2.Msg.GetSettings().GetCreatedAt())
	assert.NotNil(t, res2.Msg.GetSettings().GetModifiedAt())
	assert.Equal(t, "debug", res2.Msg.GetSettings().GetLogLevel())

	res3, err := srv.GetSettings(t.Context(), connect.NewRequest(&configpb.GetSettingsRequest{}))
	assert.NoError(t, err)
	assert.Empty(t, cmp.Diff(
		res2.Msg.GetSettings().GetCreatedAt(),
		res3.Msg.GetSettings().GetCreatedAt(),
		protocmp.Transform()), "should return created at timestamp")
}
