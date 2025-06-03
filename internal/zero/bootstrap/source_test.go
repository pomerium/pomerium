package bootstrap_test

import (
	"context"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/zero/bootstrap"
	cluster_api "github.com/pomerium/pomerium/pkg/zero/cluster"
)

func TestConfigChanges(t *testing.T) {
	t.Parallel()

	secret := []byte("secret")

	src, err := bootstrap.New(secret, nil, nil, nil)
	require.NoError(t, err)

	ptr := func(s string) *string { return &s }

	var listenerCalled bool
	src.OnConfigChange(nil, func(_ context.Context, _ *config.Config) {
		listenerCalled = true
	})

	for i, tc := range []struct {
		bootstrap                        cluster_api.BootstrapConfig
		expectChanged                    bool
		expectDatabrokerType             string
		expectDatabrokerConnectionString string
	}{
		{
			cluster_api.BootstrapConfig{},
			false,
			config.StorageInMemoryName,
			"",
		},
		{
			cluster_api.BootstrapConfig{
				DatabrokerStorageConnection: ptr("postgres://"),
			},
			true,
			config.StoragePostgresName,
			"postgres://",
		},
		{
			cluster_api.BootstrapConfig{},
			true,
			config.StorageInMemoryName,
			"",
		},
	} {
		t.Run(fmt.Sprintf("test-%d", i), func(t *testing.T) {
			listenerCalled = false
			changed := src.UpdateBootstrap(t.Context(), tc.bootstrap)
			cfg := src.GetConfig()
			assert.Equal(t, tc.expectChanged, changed, "changed")
			assert.Equal(t, tc.expectChanged, listenerCalled, "listenerCalled")
			assert.Equal(t, tc.expectDatabrokerType, cfg.Options.DataBrokerStorageType, "databroker type")
			assert.Equal(t, tc.expectDatabrokerConnectionString, cfg.Options.DataBrokerStorageConnectionString, "databroker connection string")
		})
	}
}
