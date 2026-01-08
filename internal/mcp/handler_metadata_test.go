package mcp_test

import (
	"net/http"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/require"

	"github.com/pomerium/pomerium/internal/mcp"
)

func TestWWWAuthenticate(t *testing.T) {
	t.Parallel()
	hdr := make(http.Header)
	err := mcp.SetWWWAuthenticateHeader(hdr, "example.com")
	require.NoError(t, err)
	t.Log(hdr)
	require.Empty(t, cmp.Diff(hdr, http.Header{
		"Www-Authenticate": []string{`Bearer resource_metadata="https://example.com/.well-known/oauth-protected-resource"`},
	}))
}
