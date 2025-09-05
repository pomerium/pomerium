package config_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/volatiletech/null/v9"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/testing/protocmp"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/pkg/cryptutil"
	configpb "github.com/pomerium/pomerium/pkg/grpc/config"
)

func TestDataBrokerOptions_GetStorageConnectionString(t *testing.T) {
	t.Parallel()

	t.Run("validate", func(t *testing.T) {
		t.Parallel()

		o := config.NewDefaultOptions()
		o.Services = "databroker"
		o.DataBroker.StorageType = "postgres"
		o.SharedKey = cryptutil.NewBase64Key()

		assert.ErrorContains(t, o.Validate(), "missing databroker storage backend dsn",
			"should validate DSN")

		o.DataBroker.StorageConnectionString = "DSN"
		assert.NoError(t, o.Validate(),
			"should have no error when the dsn is set")

		o.DataBroker.StorageConnectionString = ""
		o.DataBroker.StorageConnectionStringFile = "DSN_FILE"
		assert.NoError(t, o.Validate(),
			"should have no error when the dsn file is set")
	})
	t.Run("literal", func(t *testing.T) {
		t.Parallel()

		o := config.NewDefaultOptions()
		o.DataBroker.StorageConnectionString = "DSN"

		dsn, err := o.DataBroker.GetStorageConnectionString()
		assert.NoError(t, err)
		assert.Equal(t, "DSN", dsn)
	})
	t.Run("file", func(t *testing.T) {
		t.Parallel()

		dir := t.TempDir()
		fp := filepath.Join(dir, "DSN_FILE")

		o := config.NewDefaultOptions()
		o.DataBroker.StorageConnectionStringFile = fp
		o.DataBroker.StorageConnectionString = "IGNORED"

		dsn, err := o.DataBroker.GetStorageConnectionString()
		assert.Error(t, err,
			"should return an error when the file doesn't exist")
		assert.Empty(t, dsn)

		os.WriteFile(fp, []byte(`
			DSN
		`), 0o644)

		dsn, err = o.DataBroker.GetStorageConnectionString()
		assert.NoError(t, err,
			"should not return an error when the file exists")
		assert.Equal(t, "DSN", dsn,
			"should return the trimmed contents of the file")
	})
}

func TestDataBrokerOptions_FromToProto(t *testing.T) {
	t.Parallel()

	// settings that go both directions
	for _, tc := range []struct {
		proto   *configpb.Settings
		options config.DataBrokerOptions
	}{
		{
			&configpb.Settings{DatabrokerClusterNodeId: proto.String("CLUSTER_NODE_ID")},
			config.DataBrokerOptions{ClusterNodeID: null.StringFrom("CLUSTER_NODE_ID")},
		},
		{
			&configpb.Settings{DatabrokerClusterNodes: &configpb.Settings_DataBrokerClusterNodes{Nodes: []*configpb.Settings_DataBrokerClusterNode{
				{Id: "NODE_1", Url: "URL_1"},
				{Id: "NODE_2", Url: "URL_2"},
				{Id: "NODE_3", Url: "URL_3"},
			}}},
			config.DataBrokerOptions{ClusterNodes: config.DataBrokerClusterNodes{
				{ID: "NODE_1", URL: "URL_1"},
				{ID: "NODE_2", URL: "URL_2"},
				{ID: "NODE_3", URL: "URL_3"},
			}},
		},
		{
			&configpb.Settings{DatabrokerServiceUrls: []string{"URL1", "URL2", "URL3"}},
			config.DataBrokerOptions{ServiceURLs: []string{"URL1", "URL2", "URL3"}},
		},
		{
			&configpb.Settings{DatabrokerInternalServiceUrl: proto.String("INTERNAL_URL")},
			config.DataBrokerOptions{InternalServiceURL: "INTERNAL_URL"},
		},
		{
			&configpb.Settings{DatabrokerStorageType: proto.String("STORAGE_TYPE")},
			config.DataBrokerOptions{StorageType: "STORAGE_TYPE"},
		},
		{
			&configpb.Settings{DatabrokerStorageConnectionString: proto.String("STORAGE_CONNECTION_STRING")},
			config.DataBrokerOptions{StorageConnectionString: "STORAGE_CONNECTION_STRING"},
		},
		{
			&configpb.Settings{DatabrokerClusterLeaderId: proto.String("CLUSTER_LEADER_ID")},
			config.DataBrokerOptions{ClusterLeaderID: null.StringFrom("CLUSTER_LEADER_ID")},
		},
	} {
		from := config.DataBrokerOptions{}
		from.FromProto(tc.proto)
		assert.Empty(t, cmp.Diff(tc.options, from))

		to := new(configpb.Settings)
		tc.options.ToProto(to)
		assert.Empty(t, cmp.Diff(tc.proto, to, protocmp.Transform()))
	}

	// settings that can only go from options to proto
	storageConnectionStringFilePath := filepath.Join(t.TempDir(), "storage-connection-string-file")
	require.NoError(t, os.WriteFile(storageConnectionStringFilePath, []byte("STORAGE_CONNECTION_STRING_FILE"), 0o600))
	for _, tc := range []struct {
		proto   *configpb.Settings
		options config.DataBrokerOptions
	}{
		{
			&configpb.Settings{DatabrokerStorageConnectionString: proto.String("STORAGE_CONNECTION_STRING_FILE")},
			config.DataBrokerOptions{StorageConnectionStringFile: storageConnectionStringFilePath},
		},
	} {
		to := new(configpb.Settings)
		tc.options.ToProto(to)
		assert.Empty(t, cmp.Diff(tc.proto, to, protocmp.Transform()))
	}
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
			ClusterNodes: []config.DataBrokerClusterNode{
				{ID: "node-1", URL: "<INVALID>"},
			},
		}, config.ErrInvalidDataBrokerClusterNodeURL},
		{config.DataBrokerOptions{
			StorageType: "memory",
			ClusterNodes: []config.DataBrokerClusterNode{
				{ID: "node-1", URL: "http://node-1.example.com"},
			},
			ClusterNodeID: null.StringFrom("node-1"),
		}, nil},
		{config.DataBrokerOptions{
			StorageType: "memory",
			ClusterNodes: []config.DataBrokerClusterNode{
				{ID: "node-1", URL: "http://node-1.example.com"},
			},
			ClusterNodeID: null.StringFrom("node-2"),
		}, config.ErrInvalidDataBrokerClusterNodeID},
		{config.DataBrokerOptions{
			StorageType: "memory",
			ClusterNodes: []config.DataBrokerClusterNode{
				{ID: "node-1", URL: "http://node-1.example.com"},
			},
			ClusterLeaderID: null.StringFrom("node-1"),
		}, nil},
		{config.DataBrokerOptions{
			StorageType: "memory",
			ClusterNodes: []config.DataBrokerClusterNode{
				{ID: "node-1", URL: "http://node-1.example.com"},
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
