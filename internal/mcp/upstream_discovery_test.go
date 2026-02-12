package mcp

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func loadTestdata(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", name))
	require.NoError(t, err)
	return data
}

func TestFetchProtectedResourceMetadata(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		handler     http.HandlerFunc
		expected    *ProtectedResourceMetadata
		expectError string
	}{
		{
			name: "github MCP server metadata",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.Write(loadTestdata(t, "github_protected_resource_metadata.json"))
			},
			expected: &ProtectedResourceMetadata{
				ResourceName:           "GitHub MCP Server",
				Resource:               "https://api.githubcopilot.com/mcp",
				AuthorizationServers:   []string{"https://github.com/login/oauth"},
				BearerMethodsSupported: []string{"header"},
				ScopesSupported: []string{
					"gist", "notifications", "public_repo", "repo",
					"repo:status", "repo_deployment", "user", "user:email",
					"user:follow", "read:gpg_key", "read:org", "project",
				},
			},
		},
		{
			name: "minimal valid metadata",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(ProtectedResourceMetadata{
					Resource:             "https://example.com/mcp",
					AuthorizationServers: []string{"https://auth.example.com"},
				})
			},
			expected: &ProtectedResourceMetadata{
				Resource:             "https://example.com/mcp",
				AuthorizationServers: []string{"https://auth.example.com"},
			},
		},
		{
			name: "missing resource field fails validation",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(ProtectedResourceMetadata{
					AuthorizationServers: []string{"https://auth.example.com"},
				})
			},
			expectError: "resource",
		},
		{
			name: "missing authorization_servers fails validation",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(ProtectedResourceMetadata{
					Resource: "https://example.com/mcp",
				})
			},
			expectError: "authorization_servers",
		},
		{
			name: "empty authorization_servers fails validation",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(ProtectedResourceMetadata{
					Resource:             "https://example.com/mcp",
					AuthorizationServers: []string{},
				})
			},
			expectError: "authorization_servers",
		},
		{
			name: "server returns 404",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusNotFound)
			},
			expectError: "404",
		},
		{
			name: "server returns invalid JSON",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.Write([]byte(`{invalid json`))
			},
			expectError: "",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			srv := httptest.NewServer(tc.handler)
			defer srv.Close()

			result, err := FetchProtectedResourceMetadata(context.Background(), srv.Client(), srv.URL)
			if tc.expectError != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tc.expectError)
				return
			}
			if tc.expected == nil {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.expected, result)
		})
	}
}

func TestFetchAuthorizationServerMetadata(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		handler     http.HandlerFunc
		expected    *AuthorizationServerMetadata
		expectError string
	}{
		{
			name: "github authorization server metadata",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.Write(loadTestdata(t, "github_authorization_server_metadata.json"))
			},
			expected: &AuthorizationServerMetadata{
				Issuer:                        "https://github.com/login/oauth",
				AuthorizationEndpoint:         "https://github.com/login/oauth/authorize",
				TokenEndpoint:                 "https://github.com/login/oauth/access_token",
				ResponseTypesSupported:        []string{"code"},
				GrantTypesSupported:           []string{"authorization_code", "refresh_token"},
				ServiceDocumentation:          "https://docs.github.com/apps/creating-github-apps/registering-a-github-app/registering-a-github-app",
				CodeChallengeMethodsSupported: []string{"S256"},
			},
		},
		{
			name: "minimal valid AS metadata",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(AuthorizationServerMetadata{
					Issuer:                        "https://auth.example.com",
					AuthorizationEndpoint:         "https://auth.example.com/authorize",
					TokenEndpoint:                 "https://auth.example.com/token",
					ResponseTypesSupported:        []string{"code"},
					GrantTypesSupported:           []string{"authorization_code"},
					CodeChallengeMethodsSupported: []string{"S256"},
				})
			},
			expected: &AuthorizationServerMetadata{
				Issuer:                        "https://auth.example.com",
				AuthorizationEndpoint:         "https://auth.example.com/authorize",
				TokenEndpoint:                 "https://auth.example.com/token",
				ResponseTypesSupported:        []string{"code"},
				GrantTypesSupported:           []string{"authorization_code"},
				CodeChallengeMethodsSupported: []string{"S256"},
			},
		},
		{
			name: "server returns 404 on all well-known endpoints",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusNotFound)
			},
			expectError: "not found",
		},
		{
			name: "server returns invalid JSON",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.Write([]byte(`not json`))
			},
			expectError: "",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			srv := httptest.NewServer(tc.handler)
			defer srv.Close()

			// Use the server URL as the issuer URL (no path, so it should try
			// /.well-known/oauth-authorization-server then /.well-known/openid-configuration)
			result, err := FetchAuthorizationServerMetadata(context.Background(), srv.Client(), srv.URL)
			if tc.expectError != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tc.expectError)
				return
			}
			if tc.expected == nil {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.expected, result)
		})
	}
}

func TestFetchAuthorizationServerMetadata_PathBasedIssuer(t *testing.T) {
	t.Parallel()

	// Simulate GitHub's path-based issuer: https://github.com/login/oauth
	// The spec says to try:
	// 1. /.well-known/oauth-authorization-server/login/oauth
	// 2. /.well-known/openid-configuration/login/oauth
	// 3. /login/oauth/.well-known/openid-configuration

	t.Run("finds metadata at first well-known path", func(t *testing.T) {
		t.Parallel()
		var requestedPaths []string

		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			requestedPaths = append(requestedPaths, r.URL.Path)
			if r.URL.Path == "/.well-known/oauth-authorization-server/login/oauth" {
				w.Header().Set("Content-Type", "application/json")
				w.Write(loadTestdata(t, "github_authorization_server_metadata.json"))
				return
			}
			w.WriteHeader(http.StatusNotFound)
		}))
		defer srv.Close()

		result, err := FetchAuthorizationServerMetadata(context.Background(), srv.Client(), srv.URL+"/login/oauth")
		require.NoError(t, err)
		assert.Equal(t, "https://github.com/login/oauth", result.Issuer)
		// Should only have made one request since the first one succeeded
		assert.Equal(t, []string{"/.well-known/oauth-authorization-server/login/oauth"}, requestedPaths)
	})

	t.Run("falls back to second well-known path", func(t *testing.T) {
		t.Parallel()

		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/.well-known/openid-configuration/login/oauth" {
				w.Header().Set("Content-Type", "application/json")
				w.Write(loadTestdata(t, "github_authorization_server_metadata.json"))
				return
			}
			w.WriteHeader(http.StatusNotFound)
		}))
		defer srv.Close()

		result, err := FetchAuthorizationServerMetadata(context.Background(), srv.Client(), srv.URL+"/login/oauth")
		require.NoError(t, err)
		assert.Equal(t, "https://github.com/login/oauth", result.Issuer)
	})

	t.Run("falls back to third well-known path", func(t *testing.T) {
		t.Parallel()

		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/login/oauth/.well-known/openid-configuration" {
				w.Header().Set("Content-Type", "application/json")
				w.Write(loadTestdata(t, "github_authorization_server_metadata.json"))
				return
			}
			w.WriteHeader(http.StatusNotFound)
		}))
		defer srv.Close()

		result, err := FetchAuthorizationServerMetadata(context.Background(), srv.Client(), srv.URL+"/login/oauth")
		require.NoError(t, err)
		assert.Equal(t, "https://github.com/login/oauth", result.Issuer)
	})
}

func TestFetchAuthorizationServerMetadata_RequestOrder(t *testing.T) {
	t.Parallel()

	t.Run("no-path issuer tries correct endpoints in order", func(t *testing.T) {
		t.Parallel()
		var requestedPaths []string

		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			requestedPaths = append(requestedPaths, r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}))
		defer srv.Close()

		_, err := FetchAuthorizationServerMetadata(context.Background(), srv.Client(), srv.URL)
		require.Error(t, err)
		assert.Equal(t, []string{
			"/.well-known/oauth-authorization-server",
			"/.well-known/openid-configuration",
		}, requestedPaths)
	})

	t.Run("path-based issuer tries correct endpoints in order", func(t *testing.T) {
		t.Parallel()
		var requestedPaths []string

		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			requestedPaths = append(requestedPaths, r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}))
		defer srv.Close()

		_, err := FetchAuthorizationServerMetadata(context.Background(), srv.Client(), srv.URL+"/login/oauth")
		require.Error(t, err)
		assert.Equal(t, []string{
			"/.well-known/oauth-authorization-server/login/oauth",
			"/.well-known/openid-configuration/login/oauth",
			"/login/oauth/.well-known/openid-configuration",
		}, requestedPaths)
	})
}

func TestFetchAuthorizationServerMetadata_ValidationFailureFallthrough(t *testing.T) {
	t.Parallel()

	t.Run("first endpoint returns metadata failing validation, second succeeds", func(t *testing.T) {
		t.Parallel()

		// First endpoint returns metadata without S256 (fails validation),
		// second endpoint returns valid metadata.
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			switch r.URL.Path {
			case "/.well-known/oauth-authorization-server":
				// Missing S256 — fails ValidateAuthorizationServerMetadata
				json.NewEncoder(w).Encode(AuthorizationServerMetadata{
					Issuer:                        "https://auth.example.com",
					AuthorizationEndpoint:         "https://auth.example.com/authorize",
					TokenEndpoint:                 "https://auth.example.com/token",
					ResponseTypesSupported:        []string{"code"},
					GrantTypesSupported:           []string{"authorization_code"},
					CodeChallengeMethodsSupported: []string{"plain"},
				})
			case "/.well-known/openid-configuration":
				// Valid — includes S256
				json.NewEncoder(w).Encode(AuthorizationServerMetadata{
					Issuer:                        "https://auth.example.com",
					AuthorizationEndpoint:         "https://auth.example.com/authorize",
					TokenEndpoint:                 "https://auth.example.com/token",
					ResponseTypesSupported:        []string{"code"},
					GrantTypesSupported:           []string{"authorization_code"},
					CodeChallengeMethodsSupported: []string{"S256"},
				})
			default:
				w.WriteHeader(http.StatusNotFound)
			}
		}))
		defer srv.Close()

		result, err := FetchAuthorizationServerMetadata(context.Background(), srv.Client(), srv.URL)
		require.NoError(t, err)
		assert.Equal(t, "https://auth.example.com", result.Issuer)
		assert.Equal(t, []string{"S256"}, result.CodeChallengeMethodsSupported)
	})
}

func TestFetchProtectedResourceMetadata_ContextCancellation(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(ProtectedResourceMetadata{
			Resource:             "https://example.com",
			AuthorizationServers: []string{"https://auth.example.com"},
		})
	}))
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately

	_, err := FetchProtectedResourceMetadata(ctx, srv.Client(), srv.URL)
	require.Error(t, err)
}

func TestBuildProtectedResourceMetadataURLs(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		upstreamURL string
		expected    []string
		expectError bool
	}{
		{
			name:        "root URL",
			upstreamURL: "https://api.example.com",
			expected: []string{
				"https://api.example.com/.well-known/oauth-protected-resource",
			},
		},
		{
			name:        "URL with path",
			upstreamURL: "https://api.example.com/mcp",
			expected: []string{
				"https://api.example.com/.well-known/oauth-protected-resource/mcp",
				"https://api.example.com/.well-known/oauth-protected-resource",
			},
		},
		{
			name:        "URL with deeper path",
			upstreamURL: "https://api.example.com/v1/mcp/server",
			expected: []string{
				"https://api.example.com/.well-known/oauth-protected-resource/v1/mcp/server",
				"https://api.example.com/.well-known/oauth-protected-resource",
			},
		},
		{
			name:        "URL with trailing slash treated as root",
			upstreamURL: "https://api.example.com/",
			expected: []string{
				"https://api.example.com/.well-known/oauth-protected-resource",
			},
		},
		{
			name:        "invalid URL returns error",
			upstreamURL: "://invalid",
			expectError: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			result, err := BuildProtectedResourceMetadataURLs(tc.upstreamURL)
			if tc.expectError {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.expected, result)
		})
	}
}

func TestBuildAuthorizationServerMetadataURLs(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		issuerURL   string
		expected    []string
		expectError bool
	}{
		{
			name:      "root issuer (no path)",
			issuerURL: "https://auth.example.com",
			expected: []string{
				"https://auth.example.com/.well-known/oauth-authorization-server",
				"https://auth.example.com/.well-known/openid-configuration",
			},
		},
		{
			name:      "issuer with path (GitHub-style)",
			issuerURL: "https://github.com/login/oauth",
			expected: []string{
				"https://github.com/.well-known/oauth-authorization-server/login/oauth",
				"https://github.com/.well-known/openid-configuration/login/oauth",
				"https://github.com/login/oauth/.well-known/openid-configuration",
			},
		},
		{
			name:      "issuer with single path segment",
			issuerURL: "https://auth.example.com/oauth",
			expected: []string{
				"https://auth.example.com/.well-known/oauth-authorization-server/oauth",
				"https://auth.example.com/.well-known/openid-configuration/oauth",
				"https://auth.example.com/oauth/.well-known/openid-configuration",
			},
		},
		{
			name:      "issuer with trailing slash treated as root",
			issuerURL: "https://auth.example.com/",
			expected: []string{
				"https://auth.example.com/.well-known/oauth-authorization-server",
				"https://auth.example.com/.well-known/openid-configuration",
			},
		},
		{
			name:        "invalid URL returns error",
			issuerURL:   "://invalid",
			expectError: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			result, err := BuildAuthorizationServerMetadataURLs(tc.issuerURL)
			if tc.expectError {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.expected, result)
		})
	}
}

func TestValidateProtectedResourceMetadata(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		meta        *ProtectedResourceMetadata
		expectError string
	}{
		{
			name: "valid github metadata",
			meta: &ProtectedResourceMetadata{
				Resource:             "https://api.githubcopilot.com/mcp",
				AuthorizationServers: []string{"https://github.com/login/oauth"},
				ScopesSupported:      []string{"repo"},
			},
		},
		{
			name: "valid minimal metadata",
			meta: &ProtectedResourceMetadata{
				Resource:             "https://example.com",
				AuthorizationServers: []string{"https://auth.example.com"},
			},
		},
		{
			name: "missing resource",
			meta: &ProtectedResourceMetadata{
				AuthorizationServers: []string{"https://auth.example.com"},
			},
			expectError: "resource",
		},
		{
			name: "missing authorization_servers",
			meta: &ProtectedResourceMetadata{
				Resource: "https://example.com",
			},
			expectError: "authorization_servers",
		},
		{
			name: "empty authorization_servers",
			meta: &ProtectedResourceMetadata{
				Resource:             "https://example.com",
				AuthorizationServers: []string{},
			},
			expectError: "authorization_servers",
		},
		{
			name:        "nil metadata",
			meta:        nil,
			expectError: "nil",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := ValidateProtectedResourceMetadata(tc.meta)
			if tc.expectError != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tc.expectError)
				return
			}
			require.NoError(t, err)
		})
	}
}

func TestValidateAuthorizationServerMetadata(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		meta        *AuthorizationServerMetadata
		expectError string
	}{
		{
			name: "valid github AS metadata",
			meta: &AuthorizationServerMetadata{
				Issuer:                        "https://github.com/login/oauth",
				AuthorizationEndpoint:         "https://github.com/login/oauth/authorize",
				TokenEndpoint:                 "https://github.com/login/oauth/access_token",
				ResponseTypesSupported:        []string{"code"},
				GrantTypesSupported:           []string{"authorization_code", "refresh_token"},
				CodeChallengeMethodsSupported: []string{"S256"},
			},
		},
		{
			name: "valid minimal metadata",
			meta: &AuthorizationServerMetadata{
				Issuer:                        "https://auth.example.com",
				AuthorizationEndpoint:         "https://auth.example.com/authorize",
				TokenEndpoint:                 "https://auth.example.com/token",
				ResponseTypesSupported:        []string{"code"},
				GrantTypesSupported:           []string{"authorization_code"},
				CodeChallengeMethodsSupported: []string{"S256"},
			},
		},
		{
			name: "missing S256 in code_challenge_methods_supported",
			meta: &AuthorizationServerMetadata{
				Issuer:                        "https://auth.example.com",
				AuthorizationEndpoint:         "https://auth.example.com/authorize",
				TokenEndpoint:                 "https://auth.example.com/token",
				ResponseTypesSupported:        []string{"code"},
				GrantTypesSupported:           []string{"authorization_code"},
				CodeChallengeMethodsSupported: []string{"plain"},
			},
			expectError: "S256",
		},
		{
			name: "empty code_challenge_methods_supported",
			meta: &AuthorizationServerMetadata{
				Issuer:                 "https://auth.example.com",
				AuthorizationEndpoint:  "https://auth.example.com/authorize",
				TokenEndpoint:          "https://auth.example.com/token",
				ResponseTypesSupported: []string{"code"},
				GrantTypesSupported:    []string{"authorization_code"},
			},
			expectError: "S256",
		},
		{
			name: "missing authorization_code grant type",
			meta: &AuthorizationServerMetadata{
				Issuer:                        "https://auth.example.com",
				AuthorizationEndpoint:         "https://auth.example.com/authorize",
				TokenEndpoint:                 "https://auth.example.com/token",
				ResponseTypesSupported:        []string{"code"},
				GrantTypesSupported:           []string{"client_credentials"},
				CodeChallengeMethodsSupported: []string{"S256"},
			},
			expectError: "authorization_code",
		},
		{
			name: "empty grant_types_supported array fails validation",
			meta: &AuthorizationServerMetadata{
				Issuer:                        "https://auth.example.com",
				AuthorizationEndpoint:         "https://auth.example.com/authorize",
				TokenEndpoint:                 "https://auth.example.com/token",
				ResponseTypesSupported:        []string{"code"},
				GrantTypesSupported:           []string{},
				CodeChallengeMethodsSupported: []string{"S256"},
			},
			expectError: "authorization_code",
		},
		{
			name: "nil grant_types_supported defaults to authorization_code per RFC 8414",
			meta: &AuthorizationServerMetadata{
				Issuer:                        "https://auth.example.com",
				AuthorizationEndpoint:         "https://auth.example.com/authorize",
				TokenEndpoint:                 "https://auth.example.com/token",
				ResponseTypesSupported:        []string{"code"},
				CodeChallengeMethodsSupported: []string{"S256"},
			},
		},
		{
			name:        "nil metadata",
			meta:        nil,
			expectError: "nil",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := ValidateAuthorizationServerMetadata(tc.meta)
			if tc.expectError != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tc.expectError)
				return
			}
			require.NoError(t, err)
		})
	}
}
