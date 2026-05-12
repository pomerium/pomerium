package envoyconfig_test

import (
	"os"
	"path/filepath"
	"testing"

	envoy_config_core_v3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/assert"
	"google.golang.org/protobuf/testing/protocmp"

	"github.com/pomerium/pomerium/config/envoyconfig"
)

func TestGetPipe(t *testing.T) {
	t.Setenv("POMERIUM_SOCKET_DIRECTORY", "")
	assert.Empty(t, cmp.Diff(
		&envoy_config_core_v3.Pipe{Path: "@test"},
		envoyconfig.GetPipeForOS("linux", "test"),
		protocmp.Transform(),
	))
	assert.Empty(t, cmp.Diff(
		&envoy_config_core_v3.Pipe{Path: filepath.Join(os.TempDir(), "test"), Mode: 0o0600},
		envoyconfig.GetPipeForOS("darwin", "test"),
		protocmp.Transform(),
	))
	t.Setenv("POMERIUM_SOCKET_DIRECTORY", "/tmp/example")
	assert.Empty(t, cmp.Diff(
		&envoy_config_core_v3.Pipe{Path: "/tmp/example/test", Mode: 0o0600},
		envoyconfig.GetPipeForOS("linux", "test"),
		protocmp.Transform(),
	))
	assert.Empty(t, cmp.Diff(
		&envoy_config_core_v3.Pipe{Path: "/tmp/example/test", Mode: 0o0600},
		envoyconfig.GetPipeForOS("darwin", "test"),
		protocmp.Transform(),
	))
}
