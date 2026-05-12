package envoyconfig_test

import (
	"os"
	"testing"
)

func TestMain(m *testing.M) {
	os.Setenv("POMERIUM_SOCKET_DIRECTORY", "/tmp")
	os.Exit(m.Run())
}
