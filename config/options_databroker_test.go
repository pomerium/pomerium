package config_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
			&configpb.Settings{DatabrokerServiceUrls: []string{"URL1", "URL2", "URL3"}},
			config.DataBrokerOptions{URLStrings: []string{"URL1", "URL2", "URL3"}},
		},
		{
			&configpb.Settings{DatabrokerInternalServiceUrl: proto.String("INTERNAL_URL")},
			config.DataBrokerOptions{InternalURLString: "INTERNAL_URL"},
		},
		{
			&configpb.Settings{DatabrokerStorageType: proto.String("STORAGE_TYPE")},
			config.DataBrokerOptions{StorageType: "STORAGE_TYPE"},
		},
		{
			&configpb.Settings{DatabrokerStorageConnectionString: proto.String("STORAGE_CONNECTION_STRING")},
			config.DataBrokerOptions{StorageConnectionString: "STORAGE_CONNECTION_STRING"},
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
			URLString:   "<INVALID>",
		}, config.ErrInvalidDataBrokerServiceURL},
		{config.DataBrokerOptions{
			StorageType: "memory",
			URLString:   "http://databroker.example.com:5443",
		}, nil},
		{config.DataBrokerOptions{
			StorageType:       "memory",
			InternalURLString: "<INVALID>",
		}, config.ErrInvalidDataBrokerInternalServiceURL},
		{config.DataBrokerOptions{
			StorageType:       "memory",
			InternalURLString: "http://databroker.internal.example.com:5443",
		}, nil},
		{config.DataBrokerOptions{
			StorageType: "memory",
			URLStrings:  []string{"<INVALID>"},
		}, config.ErrInvalidDataBrokerServiceURL},
		{config.DataBrokerOptions{
			StorageType: "memory",
			URLStrings:  []string{"http://databroker.example.com:5443"},
		}, nil},
	} {
		err := tc.options.Validate()
		if tc.err == nil {
			assert.NoError(t, err)
		} else {
			assert.ErrorIs(t, err, tc.err)
		}
	}
}
