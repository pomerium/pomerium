package controlplane

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/anypb"

	"github.com/pomerium/pomerium/config"
	configpb "github.com/pomerium/pomerium/pkg/grpc/config"
	"github.com/pomerium/pomerium/pkg/grpc/databroker"
	sessionpb "github.com/pomerium/pomerium/pkg/grpc/session"
	"github.com/pomerium/pomerium/pkg/protoutil"
)

type stubDataBrokerClient struct {
	databroker.DataBrokerServiceClient

	getResponse *databroker.GetResponse
	syncLatest  []*databroker.SyncLatestResponse
}

func (c *stubDataBrokerClient) Get(_ context.Context, _ *databroker.GetRequest, _ ...grpc.CallOption) (*databroker.GetResponse, error) {
	return c.getResponse, nil
}

func (c *stubDataBrokerClient) SyncLatest(_ context.Context, _ *databroker.SyncLatestRequest, _ ...grpc.CallOption) (grpc.ServerStreamingClient[databroker.SyncLatestResponse], error) {
	return &stubSyncLatestStream{responses: c.syncLatest}, nil
}

type stubSyncLatestStream struct {
	grpc.ClientStream

	responses []*databroker.SyncLatestResponse
}

func (s *stubSyncLatestStream) Recv() (*databroker.SyncLatestResponse, error) {
	if len(s.responses) == 0 {
		return nil, io.EOF
	}
	res := s.responses[0]
	s.responses = s.responses[1:]
	return res, nil
}

type stubDataBrokerClientProvider struct {
	client databroker.DataBrokerServiceClient
}

func (p *stubDataBrokerClientProvider) GetLocalDatabrokerServiceClient() databroker.DataBrokerServiceClient {
	return p.client
}

func newTestDebugServer(t *testing.T, client databroker.DataBrokerServiceClient) *debugServer {
	t.Helper()
	opts := config.NewDefaultOptions()
	opts.RuntimeFlags[config.RuntimeFlagDebugAdminEndpoints] = true
	srv := newDebugServer(&config.Config{Options: opts}, nil)
	srv.SetDataBrokerClient(DataBrokerClientProvider(&stubDataBrokerClientProvider{client: client}))
	return srv
}

func newConfigRecord(t *testing.T, cfg *configpb.Config, id string) *databroker.Record {
	t.Helper()
	data, err := anypb.New(cfg)
	require.NoError(t, err)
	return &databroker.Record{
		Version: 1,
		Type:    protoutil.GetTypeURL(cfg),
		Id:      id,
		Data:    data,
	}
}

func TestDebugServer_DatabrokerRecord_RedactsSensitiveFields(t *testing.T) {
	t.Parallel()

	cfg := &configpb.Config{
		Name: "test-config",
		Settings: &configpb.Settings{
			SharedSecret: new("super-secret-shared-key"),
		},
		Routes: []*configpb.Route{{
			From:         "https://from.example.com",
			TlsClientKey: "super-secret-tls-key",
		}},
	}
	record := newConfigRecord(t, cfg, "test-id")
	srv := newTestDebugServer(t, &stubDataBrokerClient{
		getResponse: &databroker.GetResponse{Record: record},
	})

	w := httptest.NewRecorder()
	srv.ServeHTTP(w, httptest.NewRequest(http.MethodGet,
		"/databroker/"+url.PathEscape(record.Type)+"/test-id", nil))

	require.Equal(t, 200, w.Code)
	body := w.Body.String()
	assert.NotContains(t, body, "super-secret-shared-key")
	assert.NotContains(t, body, "super-secret-tls-key")
	assert.Contains(t, body, protoutil.Redacted)
	assert.Contains(t, body, "test-config", "non-sensitive fields must remain visible")
	assert.Contains(t, body, "from.example.com", "non-sensitive fields must remain visible")
}

func TestDebugServer_DatabrokerRecord_RedactsSessionTokens(t *testing.T) {
	t.Parallel()

	s := &sessionpb.Session{
		Id:     "session-id",
		UserId: "user-id",
		IdToken: &sessionpb.IDToken{
			Issuer: "https://idp.example.com",
			Raw:    "raw-id-token-jwt",
		},
		OauthToken: &sessionpb.OAuthToken{
			AccessToken:  "oauth-access-token-secret",
			TokenType:    "Bearer",
			RefreshToken: "oauth-refresh-token-secret",
		},
	}
	data, err := anypb.New(s)
	require.NoError(t, err)
	record := &databroker.Record{
		Version: 1,
		Type:    protoutil.GetTypeURL(s),
		Id:      s.Id,
		Data:    data,
	}
	srv := newTestDebugServer(t, &stubDataBrokerClient{
		getResponse: &databroker.GetResponse{Record: record},
	})

	w := httptest.NewRecorder()
	srv.ServeHTTP(w, httptest.NewRequest(http.MethodGet,
		"/databroker/"+url.PathEscape(record.Type)+"/"+url.PathEscape(record.Id), nil))

	require.Equal(t, 200, w.Code)
	body := w.Body.String()
	assert.NotContains(t, body, "oauth-access-token-secret")
	assert.NotContains(t, body, "oauth-refresh-token-secret")
	assert.NotContains(t, body, "raw-id-token-jwt")
	assert.Contains(t, body, "user-id", "non-sensitive fields must remain visible")
	assert.Contains(t, body, "idp.example.com", "non-sensitive fields must remain visible")
	assert.Contains(t, body, "Bearer", "non-sensitive fields must remain visible")
}

func TestDebugServer_VersionedConfig_RedactsSensitiveFields(t *testing.T) {
	t.Parallel()

	vc := &configpb.VersionedConfig{
		Config: &configpb.Config{
			Name: "versioned-config",
			Settings: &configpb.Settings{
				SharedSecret: new("super-secret-shared-key"),
			},
		},
	}
	data, err := anypb.New(vc)
	require.NoError(t, err)
	srv := newTestDebugServer(t, &stubDataBrokerClient{
		syncLatest: []*databroker.SyncLatestResponse{{
			Response: &databroker.SyncLatestResponse_Record{
				Record: &databroker.Record{
					Version: 1,
					Type:    protoutil.GetTypeURL(vc),
					Id:      "test-id",
					Data:    data,
				},
			},
		}},
	})

	w := httptest.NewRecorder()
	srv.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/versioned_config", nil))

	require.Equal(t, 200, w.Code)
	body := w.Body.String()
	assert.NotContains(t, body, "super-secret-shared-key")
	assert.Contains(t, body, "versioned-config", "non-sensitive fields must remain visible")
}
