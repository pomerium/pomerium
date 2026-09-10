package databroker_test

import (
	"bytes"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"connectrpc.com/connect"
	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/trace/noop"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/testing/protocmp"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/databroker"
	configpb "github.com/pomerium/pomerium/pkg/grpc/config"
	"github.com/pomerium/pomerium/pkg/grpc/config/configconnect"
	"github.com/pomerium/pomerium/pkg/storage/storagetest"
)

func TestConfigServiceAvailableLogFields(t *testing.T) {
	t.Parallel()

	srv := databroker.NewBackendServer(noop.NewTracerProvider())
	t.Cleanup(srv.Stop)
	srv.OnConfigChange(t.Context(), config.New(&config.Options{
		DataBroker: config.DataBrokerOptions{StorageType: config.StorageInMemoryName},
		SharedKey:  base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x01}, 32)),
	}))

	mux := http.NewServeMux()
	mux.Handle(configconnect.NewConfigServiceHandler(srv))
	h := httptest.NewServer(mux)
	t.Cleanup(h.Close)

	client := configconnect.NewConfigServiceClient(http.DefaultClient, h.URL)

	storagetest.TestConfigServiceAvailableLogFields(t, client)
}

func TestConfigServiceKeyPairs(t *testing.T) {
	t.Parallel()

	srv := databroker.NewBackendServer(noop.NewTracerProvider())
	t.Cleanup(srv.Stop)
	srv.OnConfigChange(t.Context(), config.New(&config.Options{
		DataBroker: config.DataBrokerOptions{StorageType: config.StorageInMemoryName},
		SharedKey:  base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x01}, 32)),
	}))

	mux := http.NewServeMux()
	mux.Handle(configconnect.NewConfigServiceHandler(srv))
	h := httptest.NewServer(mux)
	t.Cleanup(h.Close)

	client := configconnect.NewConfigServiceClient(http.DefaultClient, h.URL)

	storagetest.TestConfigServiceKeyPairs(t, client)
}

func TestConfigServicePolicies(t *testing.T) {
	t.Parallel()

	srv := databroker.NewBackendServer(noop.NewTracerProvider())
	t.Cleanup(srv.Stop)
	srv.OnConfigChange(t.Context(), config.New(&config.Options{
		DataBroker: config.DataBrokerOptions{StorageType: config.StorageInMemoryName},
		SharedKey:  base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x01}, 32)),
	}))

	mux := http.NewServeMux()
	mux.Handle(configconnect.NewConfigServiceHandler(srv))
	h := httptest.NewServer(mux)
	t.Cleanup(h.Close)

	client := configconnect.NewConfigServiceClient(http.DefaultClient, h.URL)

	storagetest.TestConfigServicePolicies(t, client)
}

func TestConfigServiceRoutes(t *testing.T) {
	t.Parallel()

	srv := databroker.NewBackendServer(noop.NewTracerProvider())
	t.Cleanup(srv.Stop)
	srv.OnConfigChange(t.Context(), config.New(&config.Options{
		DataBroker: config.DataBrokerOptions{StorageType: config.StorageInMemoryName},
		SharedKey:  base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x01}, 32)),
	}))

	mux := http.NewServeMux()
	mux.Handle(configconnect.NewConfigServiceHandler(srv))
	h := httptest.NewServer(mux)
	t.Cleanup(h.Close)

	client := configconnect.NewConfigServiceClient(http.DefaultClient, h.URL)
	storagetest.TestConfigServiceRoutes(t, client)
}

func TestConfigServiceLocalRoutes(t *testing.T) {
	t.Parallel()

	srv := databroker.NewBackendServer(noop.NewTracerProvider())
	t.Cleanup(srv.Stop)
	to, err := url.Parse("https://to.example.com")
	require.NoError(t, err)
	srv.OnConfigChange(t.Context(), config.New(&config.Options{
		DataBroker: config.DataBrokerOptions{StorageType: config.StorageInMemoryName},
		SharedKey:  base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x01}, 32)),
		Routes: []config.Policy{{
			From: "https://from.example.com",
			To: config.WeightedURLs{{
				URL: *to,
			}},
		}},
	}))

	mux := http.NewServeMux()
	mux.Handle(configconnect.NewConfigServiceHandler(srv))
	h := httptest.NewServer(mux)
	t.Cleanup(h.Close)

	client := configconnect.NewConfigServiceClient(http.DefaultClient, h.URL)

	res, err := client.ListRoutes(t.Context(), connect.NewRequest(&configpb.ListRoutesRequest{}))
	require.NoError(t, err)
	var ids []string
	for _, route := range res.Msg.Routes {
		ids = append(ids, route.GetId())
	}
	assert.Contains(t, ids, "local/route/0", "should return local routes")
}

func TestConfigServiceServiceAccounts(t *testing.T) {
	t.Parallel()

	srv := databroker.NewBackendServer(noop.NewTracerProvider())
	t.Cleanup(srv.Stop)
	srv.OnConfigChange(t.Context(), config.New(&config.Options{
		DataBroker: config.DataBrokerOptions{StorageType: config.StorageInMemoryName},
		SharedKey:  base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x01}, 32)),
	}))

	mux := http.NewServeMux()
	mux.Handle(configconnect.NewConfigServiceHandler(srv))
	h := httptest.NewServer(mux)
	t.Cleanup(h.Close)

	client := configconnect.NewConfigServiceClient(http.DefaultClient, h.URL)

	storagetest.TestConfigServiceServiceAccounts(t, client)
}

func TestConfigSettings(t *testing.T) {
	t.Parallel()

	srv := databroker.NewBackendServer(noop.NewTracerProvider())
	t.Cleanup(srv.Stop)
	srv.OnConfigChange(t.Context(), config.New(&config.Options{
		DataBroker: config.DataBrokerOptions{StorageType: config.StorageInMemoryName},
		SharedKey:  base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x01}, 32)),
	}))

	mux := http.NewServeMux()
	mux.Handle(configconnect.NewConfigServiceHandler(srv))
	h := httptest.NewServer(mux)
	t.Cleanup(h.Close)

	client := configconnect.NewConfigServiceClient(http.DefaultClient, h.URL)

	t.Run("cluster id", func(t *testing.T) {
		t.Parallel()

		_, err := client.GetSettings(t.Context(), connect.NewRequest(&configpb.GetSettingsRequest{
			For: &configpb.GetSettingsRequest_ClusterId{
				ClusterId: "CLUSTER_ID",
			},
		}))
		assert.Equal(t, connect.CodeNotFound, connect.CodeOf(err))
	})
	t.Run("namespace id", func(t *testing.T) {
		t.Parallel()

		_, err := client.GetSettings(t.Context(), connect.NewRequest(&configpb.GetSettingsRequest{
			For: &configpb.GetSettingsRequest_NamespaceId{
				NamespaceId: "NAMESPACE_ID",
			},
		}))
		assert.Equal(t, connect.CodeNotFound, connect.CodeOf(err))
	})
	t.Run("id", func(t *testing.T) {
		t.Parallel()

		_, err := client.GetSettings(t.Context(), connect.NewRequest(&configpb.GetSettingsRequest{
			For: &configpb.GetSettingsRequest_Id{
				Id: "ID",
			},
		}))
		assert.Equal(t, connect.CodeNotFound, connect.CodeOf(err))
	})
	t.Run("global id", func(t *testing.T) {
		t.Parallel()

		res, err := client.GetSettings(t.Context(), connect.NewRequest(&configpb.GetSettingsRequest{
			For: &configpb.GetSettingsRequest_Id{
				Id: databroker.GlobalSettingsID,
			},
		}))
		require.NoError(t, err)
		res.Msg.Settings.CreatedAt = nil
		res.Msg.Settings.ModifiedAt = nil
		assert.Empty(t, cmp.Diff(&configpb.Settings{
			Id: proto.String(databroker.GlobalSettingsID),
		}, res.Msg.GetSettings(), protocmp.Transform()))
	})
	t.Run("empty", func(t *testing.T) {
		t.Parallel()

		res, err := client.GetSettings(t.Context(), connect.NewRequest(&configpb.GetSettingsRequest{}))
		require.NoError(t, err)
		res.Msg.Settings.CreatedAt = nil
		res.Msg.Settings.ModifiedAt = nil
		assert.Empty(t, cmp.Diff(&configpb.Settings{
			Id: proto.String(databroker.GlobalSettingsID),
		}, res.Msg.GetSettings(), protocmp.Transform()))
	})
	t.Run("local", func(t *testing.T) {
		t.Parallel()
		res, err := client.ListSettings(t.Context(), connect.NewRequest(&configpb.ListSettingsRequest{}))
		require.NoError(t, err)
		var ids []string
		for _, settings := range res.Msg.Settings {
			ids = append(ids, settings.GetId())
		}
		assert.Contains(t, ids, "local/settings", "should return local settings")
	})

	storagetest.TestConfigServiceSettings(t, client)
}
