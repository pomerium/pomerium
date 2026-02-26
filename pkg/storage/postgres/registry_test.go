package postgres

import (
	"os"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pomerium/pomerium/internal/testutil"
	"github.com/pomerium/pomerium/pkg/grpc/registry"
	"github.com/pomerium/pomerium/pkg/protoutil"
	"github.com/pomerium/pomerium/pkg/storage/storagetest"
)

func TestRegistry(t *testing.T) {
	t.Parallel()

	if os.Getenv("GITHUB_ACTION") != "" && runtime.GOOS == "darwin" {
		t.Skip("Github action can not run docker on MacOS")
	}

	dsn := testutil.StartPostgres(t)
	backend := New(t.Context(), dsn)
	defer backend.Close()
	storagetest.TestRegistry(t, backend.RegistryServer())
}

func TestUnmarshalJSONUnknownFields(t *testing.T) {
	t.Parallel()

	data, err := protoutil.UnmarshalAnyJSON([]byte(`
	{
		"@type": "type.googleapis.com/registry.Service",
		"kind": "AUTHENTICATE",
		"endpoint": "endpoint",
		"unknown_field": true
	  }
	`))
	require.NoError(t, err)
	var val registry.Service
	require.NoError(t, data.UnmarshalTo(&val))
	assert.Equal(t, registry.ServiceKind_AUTHENTICATE, val.Kind)
	assert.Equal(t, "endpoint", val.Endpoint)
}
