package mcp_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/require"

	"github.com/pomerium/pomerium/internal/mcp"
)

func TestWWWAuthenticate(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		host        string
		requestPath string
		expected    string
	}{
		{
			name:        "root path",
			host:        "example.com",
			requestPath: "/",
			expected:    `Bearer resource_metadata="https://example.com/.well-known/oauth-protected-resource"`,
		},
		{
			name:        "empty path",
			host:        "example.com",
			requestPath: "",
			expected:    `Bearer resource_metadata="https://example.com/.well-known/oauth-protected-resource"`,
		},
		{
			name:        "path-based MCP server",
			host:        "example.com",
			requestPath: "/mcp",
			expected:    `Bearer resource_metadata="https://example.com/.well-known/oauth-protected-resource/mcp"`,
		},
		{
			name:        "nested path",
			host:        "example.com",
			requestPath: "/api/mcp/v1",
			expected:    `Bearer resource_metadata="https://example.com/.well-known/oauth-protected-resource/api/mcp/v1"`,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			hdr := make(http.Header)
			err := mcp.SetWWWAuthenticateHeader(hdr, tc.host, tc.requestPath)
			require.NoError(t, err)
			require.Empty(t, cmp.Diff(hdr, http.Header{
				"Www-Authenticate": []string{tc.expected},
			}))
		})
	}
}

func TestAuthorizationServerMetadataCapabilities(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name             string
		opts             mcp.MetadataOptions
		wantCIMD         bool
		wantRegistration string
	}{
		{
			name:             "defaults advertise cimd only",
			opts:             mcp.MetadataOptions{CIMDEnabled: true},
			wantCIMD:         true,
			wantRegistration: "",
		},
		{
			name:             "both advertised",
			opts:             mcp.MetadataOptions{CIMDEnabled: true, DCREnabled: true},
			wantCIMD:         true,
			wantRegistration: "https://example.com/.pomerium/mcp/register",
		},
		{
			// Clients that prefer CIMD whenever it is advertised only fall back to
			// DCR when the field is absent entirely.
			name:             "dcr only omits cimd",
			opts:             mcp.MetadataOptions{DCREnabled: true},
			wantCIMD:         false,
			wantRegistration: "https://example.com/.pomerium/mcp/register",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			req := httptest.NewRequest(http.MethodGet, "https://example.com"+mcp.WellKnownAuthorizationServerEndpoint, nil)
			req.Host = "example.com"
			w := httptest.NewRecorder()

			mcp.AuthorizationServerMetadataHandler(mcp.DefaultPrefix, tc.opts).ServeHTTP(w, req)
			require.Equal(t, http.StatusOK, w.Code)

			var got mcp.AuthorizationServerMetadata
			require.NoError(t, json.Unmarshal(w.Body.Bytes(), &got))
			require.Equal(t, tc.wantCIMD, got.ClientIDMetadataDocumentSupported)
			require.Equal(t, tc.wantRegistration, got.RegistrationEndpoint)

			// omitempty: the field must be absent, not false, so clients cannot
			// read it as an explicit capability declaration.
			var raw map[string]any
			require.NoError(t, json.Unmarshal(w.Body.Bytes(), &raw))
			_, present := raw["client_id_metadata_document_supported"]
			require.Equal(t, tc.wantCIMD, present)
		})
	}
}
