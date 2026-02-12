package databroker_test

import (
	"bytes"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"testing"

	"connectrpc.com/connect"
	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/assert"
	"go.opentelemetry.io/otel/trace/noop"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/testing/protocmp"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/databroker"
	configpb "github.com/pomerium/pomerium/pkg/grpc/config"
	"github.com/pomerium/pomerium/pkg/grpc/config/configconnect"
	"github.com/pomerium/pomerium/pkg/storage/storagetest"
)

func TestConfigServiceKeyPairs(t *testing.T) {
	t.Parallel()

	srv := databroker.NewBackendServer(noop.NewTracerProvider())
	t.Cleanup(srv.Stop)
	srv.OnConfigChange(t.Context(), &config.Config{
		Options: &config.Options{
			DataBroker: config.DataBrokerOptions{StorageType: config.StorageInMemoryName},
			SharedKey:  base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x01}, 32)),
		},
	})

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
	srv.OnConfigChange(t.Context(), &config.Config{
		Options: &config.Options{
			DataBroker: config.DataBrokerOptions{StorageType: config.StorageInMemoryName},
			SharedKey:  base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x01}, 32)),
		},
	})

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
	srv.OnConfigChange(t.Context(), &config.Config{
		Options: &config.Options{
			DataBroker: config.DataBrokerOptions{StorageType: config.StorageInMemoryName},
			SharedKey:  base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x01}, 32)),
		},
	})

	mux := http.NewServeMux()
	mux.Handle(configconnect.NewConfigServiceHandler(srv))
	h := httptest.NewServer(mux)
	t.Cleanup(h.Close)

	client := configconnect.NewConfigServiceClient(http.DefaultClient, h.URL)

	storagetest.TestConfigServiceRoutes(t, client)
}

func TestConfigServiceServiceAccounts(t *testing.T) {
	t.Parallel()

	srv := databroker.NewBackendServer(noop.NewTracerProvider())
	t.Cleanup(srv.Stop)
	srv.OnConfigChange(t.Context(), &config.Config{
		Options: &config.Options{
			DataBroker: config.DataBrokerOptions{StorageType: config.StorageInMemoryName},
			SharedKey:  base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x01}, 32)),
		},
	})

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
	srv.OnConfigChange(t.Context(), &config.Config{
		Options: &config.Options{
			DataBroker: config.DataBrokerOptions{StorageType: config.StorageInMemoryName},
			SharedKey:  base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x01}, 32)),
		},
	})

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
		assert.NoError(t, err)
		assert.Empty(t, cmp.Diff(&configpb.Settings{
			Id: proto.String(databroker.GlobalSettingsID),
		}, res.Msg.GetSettings(), protocmp.Transform()))
	})
	t.Run("empty", func(t *testing.T) {
		t.Parallel()

		res, err := client.GetSettings(t.Context(), connect.NewRequest(&configpb.GetSettingsRequest{}))
		assert.NoError(t, err)
		assert.Empty(t, cmp.Diff(&configpb.Settings{
			Id: proto.String(databroker.GlobalSettingsID),
		}, res.Msg.GetSettings(), protocmp.Transform()))
	})
}
