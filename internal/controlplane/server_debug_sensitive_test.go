package controlplane

import (
	"net/http"
	"net/http/httptest"
	"sync"
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
)

func TestConfigDumpScrubsSensitiveFields(t *testing.T) {
	const canary = "DEBUG_IDP_CLIENT_SECRET_CANARY"
	const upstreamUsernameCanary = "DEBUG_UPSTREAM_USERNAME_CANARY"
	const upstreamPasswordCanary = "DEBUG_UPSTREAM_PASSWORD_CANARY"
	const upstreamTokenCanary = "DEBUG_UPSTREAM_TOKEN_CANARY"

	options := config.NewDefaultOptions()
	policy := config.Policy{
		From: "https://app.example.com",
		To: mustDebugWeightedURLs(t,
			"https://"+upstreamUsernameCanary+":"+upstreamPasswordCanary+"@app.internal",
			"https://"+upstreamTokenCanary+"@backup.internal",
		),
	}
	policy.IDPClientID = "public-client-id"
	policy.IDPClientSecret = canary
	options.Policies = []config.Policy{policy}
	cfg := &config.Config{Options: options}

	recorder := httptest.NewRecorder()
	new(debugServer).configDumpHandler(cfg)(recorder, httptest.NewRequest(http.MethodGet, "/config_dump", nil))

	assert.Equal(t, 200, recorder.Code)
	assert.NotContains(t, recorder.Body.String(), canary)
	assert.NotContains(t, recorder.Body.String(), upstreamUsernameCanary)
	assert.NotContains(t, recorder.Body.String(), upstreamPasswordCanary)
	assert.NotContains(t, recorder.Body.String(), upstreamTokenCanary)
	assert.Contains(t, recorder.Body.String(), "public-client-id")
	require.Equal(t, canary, cfg.Options.Policies[0].IDPClientSecret,
		"presentation scrubbing must not mutate live configuration")
}

func TestConfigDumpConcurrentScrubbingDoesNotMutateLiveConfig(t *testing.T) {
	const canary = "CONCURRENT_IDP_CLIENT_SECRET_CANARY"
	options := config.NewDefaultOptions()
	policy := config.Policy{
		From: "https://app.example.com",
		To:   mustDebugWeightedURLs(t, "https://app.internal"),
	}
	policy.IDPClientSecret = canary
	options.Policies = []config.Policy{policy}
	cfg := &config.Config{Options: options}
	handler := new(debugServer).configDumpHandler(cfg)

	var wg sync.WaitGroup
	for range 16 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			recorder := httptest.NewRecorder()
			handler(recorder, httptest.NewRequest(http.MethodGet, "/config_dump", nil))
			assert.Equal(t, http.StatusOK, recorder.Code)
			assert.NotContains(t, recorder.Body.String(), canary)
		}()
	}
	wg.Wait()
	require.Equal(t, canary, cfg.Options.Policies[0].IDPClientSecret)
}

func TestVersionedConfigRenderingScrubsSensitiveFields(t *testing.T) {
	const canary = "VERSIONED_IDP_CLIENT_SECRET_CANARY"
	const upstreamUsernameCanary = "VERSIONED_UPSTREAM_USERNAME_CANARY"
	const upstreamPasswordCanary = "VERSIONED_UPSTREAM_PASSWORD_CANARY"
	const upstreamTokenCanary = "VERSIONED_UPSTREAM_TOKEN_CANARY"
	clientID := "public-client-id"
	secret := canary

	data := &versionedConfigData{}
	rendered := data.RenderVersionedConfig(&configpb.VersionedConfig{
		Config: &configpb.Config{Routes: []*configpb.Route{{
			From: "https://app.example.com",
			To: []string{
				"https://" + upstreamUsernameCanary + ":" + upstreamPasswordCanary + "@app.internal",
				"https://" + upstreamTokenCanary + "@backup.internal",
			},
			IdpClientId:     &clientID,
			IdpClientSecret: &secret,
		}}},
	})

	assert.NotContains(t, string(rendered), canary)
	assert.NotContains(t, string(rendered), upstreamUsernameCanary)
	assert.NotContains(t, string(rendered), upstreamPasswordCanary)
	assert.NotContains(t, string(rendered), upstreamTokenCanary)
	assert.Contains(t, string(rendered), "public-client-id")
}

func TestDatabrokerRecordRenderingScrubsSensitiveFields(t *testing.T) {
	const canary = "DATABROKER_IDP_CLIENT_SECRET_CANARY"
	const upstreamUsernameCanary = "DATABROKER_UPSTREAM_USERNAME_CANARY"
	const upstreamPasswordCanary = "DATABROKER_UPSTREAM_PASSWORD_CANARY"
	const upstreamTokenCanary = "DATABROKER_UPSTREAM_TOKEN_CANARY"
	clientID := "public-client-id"
	secret := canary

	configData, err := anypb.New(&configpb.Config{Routes: []*configpb.Route{{
		From: "https://app.example.com",
		To: []string{
			"https://" + upstreamUsernameCanary + ":" + upstreamPasswordCanary + "@app.internal",
			"https://" + upstreamTokenCanary + "@backup.internal",
		},
		IdpClientId:     &clientID,
		IdpClientSecret: &secret,
	}}})
	require.NoError(t, err)
	record := &databroker.Record{Type: "type.googleapis.com/pomerium.config.Config", Id: "config", Data: configData}

	presentation := scrubSensitiveDatabrokerRecord(record)
	rendered, err := protojson.Marshal(presentation)
	require.NoError(t, err)
	assert.NotContains(t, string(rendered), canary)
	assert.NotContains(t, string(rendered), upstreamUsernameCanary)
	assert.NotContains(t, string(rendered), upstreamPasswordCanary)
	assert.NotContains(t, string(rendered), upstreamTokenCanary)
	assert.Contains(t, string(rendered), "public-client-id")

	original, err := protojson.Marshal(record)
	require.NoError(t, err)
	assert.Contains(t, string(original), canary, "presentation scrubbing must not mutate the live record")
}

func TestDatabrokerRecordRenderingScrubsDoubleWrappedAny(t *testing.T) {
	const canary = "DOUBLE_WRAPPED_ANY_IDP_CLIENT_SECRET_CANARY"
	clientID := "public-client-id"
	secret := canary

	configData, err := anypb.New(&configpb.Config{Routes: []*configpb.Route{{
		From:            "https://app.example.com",
		To:              []string{"https://app.internal"},
		IdpClientId:     &clientID,
		IdpClientSecret: &secret,
	}}})
	require.NoError(t, err)
	doubleWrapped, err := anypb.New(configData)
	require.NoError(t, err)
	record := &databroker.Record{
		Type: "type.googleapis.com/google.protobuf.Any",
		Id:   "nested-config",
		Data: doubleWrapped,
	}

	presentation := scrubSensitiveDatabrokerRecord(record)
	rendered, err := protojson.Marshal(presentation)
	require.NoError(t, err)
	assert.NotContains(t, string(rendered), canary)
	assert.Contains(t, string(rendered), "public-client-id")

	original, err := protojson.Marshal(record)
	require.NoError(t, err)
	assert.Contains(t, string(original), canary, "presentation scrubbing must not mutate the live nested Any")
}

func TestDatabrokerRecordRenderingDropsUnknownWireFieldsWithoutMutation(t *testing.T) {
	const canary = "UNKNOWN_WIRE_SECRET_CANARY"
	unknown := protowire.AppendTag(nil, 65000, protowire.BytesType)
	unknown = protowire.AppendBytes(unknown, []byte(canary))
	cfg := &configpb.Config{Routes: []*configpb.Route{{
		From: "https://app.example.com",
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

	first := scrubSensitiveDatabrokerRecord(record)
	second := scrubSensitiveDatabrokerRecord(record)
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
