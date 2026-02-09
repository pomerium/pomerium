package databroker_test

import (
	"bytes"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"testing"

	"go.opentelemetry.io/otel/trace/noop"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/databroker"
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
