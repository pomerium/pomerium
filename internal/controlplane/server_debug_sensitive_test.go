package controlplane

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"

	"github.com/pomerium/pomerium/config"
	configpb "github.com/pomerium/pomerium/pkg/grpc/config"
	"github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/nullable"
)

func TestConfigDumpScrubsSensitiveFields(t *testing.T) {
	const canary = "POSTGRES_DEBUG_PASSWORD_CANARY"

	options := config.NewDefaultOptions()
	options.Policies = []config.Policy{{
		From: "postgres://db.example.com",
		To:   mustDebugWeightedURLs(t, "postgres://postgres.internal:5432"),
		RouteOptions: config.RouteOptions{
			Postgres: nullable.From(config.PostgresRouteSettings{
				AuthenticationMode: nullable.From(configpb.PostgresAuthenticationMode_POSTGRES_AUTHENTICATION_MODE_MANAGED),
				Username:           nullable.From("db-user"),
				Database:           nullable.From("app-db"),
				Password:           nullable.From(canary),
			}),
		},
	}}
	cfg := &config.Config{Options: options}

	recorder := httptest.NewRecorder()
	new(debugServer).configDumpHandler(cfg)(recorder, httptest.NewRequest(http.MethodGet, "/config_dump", nil))

	assert.Equal(t, 200, recorder.Code)
	assert.NotContains(t, recorder.Body.String(), canary)
	assert.Contains(t, recorder.Body.String(), "db-user")
}

func TestVersionedConfigRenderingScrubsSensitiveFields(t *testing.T) {
	const canary = "POSTGRES_VERSIONED_PASSWORD_CANARY"

	data := &versionedConfigData{}
	rendered := data.RenderVersionedConfig(&configpb.VersionedConfig{
		Config: &configpb.Config{Routes: []*configpb.Route{{
			From: "postgres://db.example.com",
			To:   []string{"postgres://postgres.internal:5432"},
			Postgres: &configpb.PostgresRouteSettings{
				AuthenticationMode: configpb.PostgresAuthenticationMode_POSTGRES_AUTHENTICATION_MODE_MANAGED.Enum(),
				Username:           "db-user",
				Database:           "app-db",
				Password:           canary,
			},
		}}},
	})

	assert.NotContains(t, string(rendered), canary)
	assert.Contains(t, string(rendered), "db-user")
}

func TestDatabrokerRecordRenderingScrubsSensitiveFields(t *testing.T) {
	const canary = "POSTGRES_DATABROKER_PASSWORD_CANARY"

	configData, err := anypb.New(&configpb.Config{Routes: []*configpb.Route{{
		From: "postgres://db.example.com",
		To:   []string{"postgres://postgres.internal:5432"},
		Postgres: &configpb.PostgresRouteSettings{
			AuthenticationMode: configpb.PostgresAuthenticationMode_POSTGRES_AUTHENTICATION_MODE_MANAGED.Enum(),
			Username:           "db-user",
			Database:           "app-db",
			Password:           canary,
		},
	}}})
	require.NoError(t, err)
	record := &databroker.Record{Type: "type.googleapis.com/pomerium.config.Config", Id: "config", Data: configData}

	presentation, err := scrubSensitiveDatabrokerRecord(record)
	require.NoError(t, err)
	rendered, err := protojson.Marshal(presentation)
	require.NoError(t, err)
	assert.NotContains(t, string(rendered), canary)
	assert.Contains(t, string(rendered), "db-user")

	original, err := protojson.Marshal(record)
	require.NoError(t, err)
	assert.Contains(t, string(original), canary, "presentation scrubbing must not mutate the live record")
}

func TestDatabrokerRecordRenderingScrubsDoubleWrappedAny(t *testing.T) {
	const canary = "POSTGRES_DOUBLE_WRAPPED_ANY_PASSWORD_CANARY"

	configData, err := anypb.New(&configpb.Config{Routes: []*configpb.Route{{
		From: "postgres://db.example.com",
		To:   []string{"postgres://postgres.internal:5432"},
		Postgres: &configpb.PostgresRouteSettings{
			AuthenticationMode: configpb.PostgresAuthenticationMode_POSTGRES_AUTHENTICATION_MODE_MANAGED.Enum(),
			Username:           "db-user",
			Database:           "app-db",
			Password:           canary,
		},
	}}})
	require.NoError(t, err)
	doubleWrapped, err := anypb.New(configData)
	require.NoError(t, err)
	record := &databroker.Record{
		Type: "type.googleapis.com/google.protobuf.Any",
		Id:   "nested-config",
		Data: doubleWrapped,
	}

	presentation, err := scrubSensitiveDatabrokerRecord(record)
	require.NoError(t, err)
	rendered, err := protojson.Marshal(presentation)
	require.NoError(t, err)
	assert.NotContains(t, string(rendered), canary)
	assert.Contains(t, string(rendered), "db-user")

	original, err := protojson.Marshal(record)
	require.NoError(t, err)
	assert.Contains(t, string(original), canary, "presentation scrubbing must not mutate the live nested Any")
}

func TestDatabrokerRecordRenderingDropsUnknownWireFieldsWithoutMutation(t *testing.T) {
	const canary = "POSTGRES_UNKNOWN_WIRE_PASSWORD_CANARY"
	unknown := protowire.AppendTag(nil, 65000, protowire.BytesType)
	unknown = protowire.AppendBytes(unknown, []byte(canary))
	cfg := &configpb.Config{Routes: []*configpb.Route{{
		From: "postgres://db.example.com",
	}}}
	cfg.Routes[0].ProtoReflect().SetUnknown(unknown)
	configData, err := anypb.New(cfg)
	require.NoError(t, err)
	record := &databroker.Record{
		Type: "type.googleapis.com/pomerium.config.Config",
		Id:   "version-skewed-config",
		Data: configData,
	}
	record.ProtoReflect().SetUnknown(unknown)
	originalWire, err := proto.MarshalOptions{Deterministic: true}.Marshal(record)
	require.NoError(t, err)
	require.Contains(t, string(originalWire), canary)

	first, err := scrubSensitiveDatabrokerRecord(record)
	require.NoError(t, err)
	second, err := scrubSensitiveDatabrokerRecord(record)
	require.NoError(t, err)
	firstWire, err := proto.MarshalOptions{Deterministic: true}.Marshal(first)
	require.NoError(t, err)
	secondWire, err := proto.MarshalOptions{Deterministic: true}.Marshal(second)
	require.NoError(t, err)
	assert.Equal(t, firstWire, secondWire, "presentation scrubbing must be deterministic")
	assert.NotContains(t, string(firstWire), canary)

	afterWire, err := proto.MarshalOptions{Deterministic: true}.Marshal(record)
	require.NoError(t, err)
	assert.Equal(t, originalWire, afterWire, "presentation scrubbing must not mutate the live record")
	assert.Contains(t, string(afterWire), canary)
}

func mustDebugWeightedURLs(t testing.TB, values ...string) config.WeightedURLs {
	t.Helper()
	urls, err := config.ParseWeightedUrls(values...)
	if err != nil {
		t.Fatal(err)
	}
	return urls
}
