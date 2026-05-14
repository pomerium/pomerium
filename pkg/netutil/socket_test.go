package netutil_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/pomerium/pomerium/pkg/netutil"
)

func TestGetUnixSocketPath(t *testing.T) {
	t.Setenv("POMERIUM_SOCKET_DIRECTORY", "")
	assert.Equal(t, "@test", netutil.GetUnixSocketPathForOS("linux", "test"))
	assert.Equal(t, filepath.Join(os.TempDir(), "test"), netutil.GetUnixSocketPathForOS("darwin", "test"))
	t.Setenv("POMERIUM_SOCKET_DIRECTORY", "/tmp/example")
	assert.Equal(t, "/tmp/example/test", netutil.GetUnixSocketPathForOS("linux", "test"))
	assert.Equal(t, "/tmp/example/test", netutil.GetUnixSocketPathForOS("darwin", "test"))
}
