package mcp_test

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/assert"
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

func TestAuthorizationServerMetadataHandler(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/.well-known/oauth-protected-resource", nil)
	r.Host = "my-domain.internal"

	t.Run("DCR disabled", func(t *testing.T) {
		h := mcp.AuthorizationServerMetadataHandler("/prefix", false)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		res := w.Result()
		assert.Equal(t, http.StatusOK, res.StatusCode)
		b, err := io.ReadAll(res.Body)
		require.NoError(t, err)
		assert.JSONEq(t, `{
			"authorization_endpoint": "https://my-domain.internal/prefix/authorize",
			"authorization_response_iss_parameter_supported": true,
			"client_id_metadata_document_supported": true,
			"code_challenge_methods_supported": [ "S256" ],
			"grant_types_supported": [ "authorization_code", "refresh_token" ],
			"issuer": "https://my-domain.internal",
			"response_types_supported": [ "code" ],
			"revocation_endpoint": "https://my-domain.internal/prefix/revoke",
			"revocation_endpoint_auth_methods_supported": [ "client_secret_post" ],
			"service_documentation": "https://pomerium.com/docs",
			"token_endpoint": "https://my-domain.internal/prefix/token",
			"token_endpoint_auth_methods_supported": [ "private_key_jwt", "none" ],
			"token_endpoint_auth_signing_alg_values_supported": [ "RS256", "ES256", "EdDSA"]
		}`, string(b))
	})

	t.Run("DCR enabled", func(t *testing.T) {
		h := mcp.AuthorizationServerMetadataHandler("/prefix", true)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		res := w.Result()
		assert.Equal(t, http.StatusOK, res.StatusCode)
		b, err := io.ReadAll(res.Body)
		require.NoError(t, err)
		assert.JSONEq(t, `{
			"authorization_endpoint": "https://my-domain.internal/prefix/authorize",
			"authorization_response_iss_parameter_supported": true,
			"client_id_metadata_document_supported": true,
			"code_challenge_methods_supported": [ "S256" ],
			"grant_types_supported": [ "authorization_code", "refresh_token" ],
			"issuer": "https://my-domain.internal",
			"registration_endpoint": "https://my-domain.internal/prefix/register",
			"response_types_supported": [ "code" ],
			"revocation_endpoint": "https://my-domain.internal/prefix/revoke",
			"revocation_endpoint_auth_methods_supported": [ "client_secret_post" ],
			"service_documentation": "https://pomerium.com/docs",
			"token_endpoint": "https://my-domain.internal/prefix/token",
			"token_endpoint_auth_methods_supported": [ "private_key_jwt", "client_secret_basic", "none" ],
			"token_endpoint_auth_signing_alg_values_supported": [ "RS256", "ES256", "EdDSA"]
		}`, string(b))
	})
}
