package config_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/volatiletech/null/v9"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/pkg/cryptutil"
)

func TestDataBrokerOptions_GetStorageConnectionString(t *testing.T) {
	t.Parallel()

	t.Run("validate", func(t *testing.T) {
		t.Parallel()

		o := config.NewDefaultOptions()
		o.Services = "databroker"
		o.SharedKey = cryptutil.NewBase64Key()

		o.DatabrokerStorageType = new("memory")
		o.DatabrokerStorageConnectionString = nil
		assert.NoError(t, o.Validate(),
			"should not require a storage connection string for memory")

		o.DatabrokerStorageType = new("file")
		o.DatabrokerStorageConnectionString = nil
		assert.NoError(t, o.Validate(),
			"should not require a storage connection string for file")

		o.DatabrokerStorageType = new("postgres")
		o.DatabrokerStorageConnectionString = nil
		assert.ErrorContains(t, o.Validate(), "missing databroker storage backend dsn",
			"should validate DSN")
		o.DatabrokerStorageConnectionString = new("DSN")
		assert.NoError(t, o.Validate(),
			"should have no error when the dsn is set")

		o.DatabrokerStorageConnectionString = nil
		o.DatabrokerStorageConnectionString = new("DSN_FILE")
		assert.NoError(t, o.Validate(),
			"should have no error when the dsn file is set")
	})
	t.Run("literal", func(t *testing.T) {
		t.Parallel()

		o := config.NewDefaultOptions()
		o.DatabrokerStorageConnectionString = new("DSN")

		dsn, err := o.GetDataBrokerOptions().GetStorageConnectionString()
		assert.NoError(t, err)
		assert.Equal(t, "DSN", dsn)
	})
	t.Run("file", func(t *testing.T) {
		t.Parallel()

		dir := t.TempDir()
		fp := filepath.Join(dir, "DSN_FILE")

		o := config.NewDefaultOptions()
		o.DatabrokerStorageConnectionStringFile = new(fp)
		o.DatabrokerStorageConnectionString = new("IGNORED")

		dsn, err := o.GetDataBrokerOptions().GetStorageConnectionString()
		assert.Error(t, err,
			"should return an error when the file doesn't exist")
		assert.Empty(t, dsn)

		os.WriteFile(fp, []byte(`
			DSN
		`), 0o644)

		dsn, err = o.GetDataBrokerOptions().GetStorageConnectionString()
		assert.NoError(t, err,
			"should not return an error when the file exists")
		assert.Equal(t, "DSN", dsn,
			"should return the trimmed contents of the file")
	})
}

func TestDataBrokerOptions_Validate(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		options config.DataBrokerOptions
		err     error
	}{
		{config.DataBrokerOptions{}, config.ErrUnknownDataBrokerStorageType},
		{config.DataBrokerOptions{
			StorageType: "unknown",
		}, config.ErrUnknownDataBrokerStorageType},
		{config.DataBrokerOptions{
			StorageType: "memory",
		}, nil},
		{config.DataBrokerOptions{
			StorageType: "postgres",
		}, config.ErrMissingDataBrokerStorageConnectionString},
		{config.DataBrokerOptions{
			StorageType:             "postgres",
			StorageConnectionString: "postgres://pomerium:password@postgres:5432/test",
		}, nil},
		{config.DataBrokerOptions{
			StorageType: "memory",
			ServiceURL:  "<INVALID>",
		}, config.ErrInvalidDataBrokerServiceURL},
		{config.DataBrokerOptions{
			StorageType: "memory",
			ServiceURL:  "http://databroker.example.com:5443",
		}, nil},
		{config.DataBrokerOptions{
			StorageType:        "memory",
			InternalServiceURL: "<INVALID>",
		}, config.ErrInvalidDataBrokerInternalServiceURL},
		{config.DataBrokerOptions{
			StorageType:        "memory",
			InternalServiceURL: "http://databroker.internal.example.com:5443",
		}, nil},
		{config.DataBrokerOptions{
			StorageType: "memory",
			ServiceURLs: []string{"<INVALID>"},
		}, config.ErrInvalidDataBrokerServiceURL},
		{config.DataBrokerOptions{
			StorageType: "memory",
			ServiceURLs: []string{"http://databroker.example.com:5443"},
		}, nil},
		{config.DataBrokerOptions{
			StorageType: "memory",
			ClusterNodes: &config.Settings_DataBrokerClusterNodes{
				Nodes: []config.Settings_DataBrokerClusterNode{
					{ID: "node-1", GRPCAddress: "<INVALID>"},
				},
			},
		}, config.ErrInvalidDataBrokerClusterNodeGRPCAddress},
		{config.DataBrokerOptions{
			StorageType: "memory",
			ClusterNodes: &config.Settings_DataBrokerClusterNodes{
				Nodes: []config.Settings_DataBrokerClusterNode{
					{ID: "node-1", GRPCAddress: "http://node-1.example.com"},
				},
			},
			ClusterNodeID: null.StringFrom("node-1"),
		}, nil},
		{config.DataBrokerOptions{
			StorageType: "memory",
			ClusterNodes: &config.Settings_DataBrokerClusterNodes{
				Nodes: []config.Settings_DataBrokerClusterNode{
					{ID: "node-1", GRPCAddress: "http://node-1.example.com"},
				},
			},
			ClusterNodeID: null.StringFrom("node-2"),
		}, config.ErrInvalidDataBrokerClusterNodeID},
		{config.DataBrokerOptions{
			StorageType: "memory",
			ClusterNodes: &config.Settings_DataBrokerClusterNodes{
				Nodes: []config.Settings_DataBrokerClusterNode{
					{ID: "node-1", GRPCAddress: "http://node-1.example.com"},
				},
			},
			ClusterLeaderID: null.StringFrom("node-1"),
		}, nil},
		{config.DataBrokerOptions{
			StorageType: "memory",
			ClusterNodes: &config.Settings_DataBrokerClusterNodes{
				Nodes: []config.Settings_DataBrokerClusterNode{
					{ID: "node-1", GRPCAddress: "http://node-1.example.com"},
				},
			},
			ClusterLeaderID: null.StringFrom("node-2"),
		}, config.ErrInvalidDataBrokerClusterLeaderID},
	} {
		err := tc.options.Validate()
		if tc.err == nil {
			assert.NoError(t, err)
		} else {
			assert.ErrorIs(t, err, tc.err)
		}
	}
}
