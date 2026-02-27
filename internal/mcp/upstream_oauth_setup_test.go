package mcp

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSelectScopes(t *testing.T) {
	t.Parallel()

	t.Run("www-authenticate scope takes priority", func(t *testing.T) {
		t.Parallel()
		result := selectScopes(
			&WWWAuthenticateParams{Scope: []string{"openid", "profile"}},
			[]string{"read", "write"},
		)
		assert.Equal(t, []string{"openid", "profile"}, result)
	})

	t.Run("falls back to PRM scopes", func(t *testing.T) {
		t.Parallel()
		result := selectScopes(nil, []string{"read", "write"})
		assert.Equal(t, []string{"read", "write"}, result)
	})

	t.Run("nil www-authenticate falls back to PRM scopes", func(t *testing.T) {
		t.Parallel()
		result := selectScopes(
			&WWWAuthenticateParams{},
			[]string{"read"},
		)
		assert.Equal(t, []string{"read"}, result)
	})

	t.Run("returns nil when no scopes available", func(t *testing.T) {
		t.Parallel()
		result := selectScopes(nil, nil)
		assert.Nil(t, result)
	})
}

func TestBuildAuthorizationURL(t *testing.T) {
	t.Parallel()

	t.Run("full params", func(t *testing.T) {
		t.Parallel()
		result := buildAuthorizationURL("https://auth.example.com/authorize", &authorizationURLParams{
			ClientID:            "https://proxy.example.com/.pomerium/mcp/client/metadata.json",
			RedirectURI:         "https://proxy.example.com/.pomerium/mcp/client/oauth/callback",
			Scopes:              []string{"read", "write"},
			State:               "state-123",
			CodeChallenge:       "challenge-abc",
			CodeChallengeMethod: "S256",
			Resource:            "https://api.example.com",
		})
		assert.Contains(t, result, "https://auth.example.com/authorize?")
		assert.Contains(t, result, "client_id=")
		assert.Contains(t, result, "response_type=code")
		assert.Contains(t, result, "redirect_uri=")
		assert.Contains(t, result, "scope=read+write")
		assert.Contains(t, result, "state=state-123")
		assert.Contains(t, result, "code_challenge=challenge-abc")
		assert.Contains(t, result, "code_challenge_method=S256")
		assert.Contains(t, result, "resource=")
	})

	t.Run("no scopes", func(t *testing.T) {
		t.Parallel()
		result := buildAuthorizationURL("https://auth.example.com/authorize", &authorizationURLParams{
			ClientID:            "client-id",
			RedirectURI:         "https://example.com/callback",
			State:               "state-123",
			CodeChallenge:       "challenge",
			CodeChallengeMethod: "S256",
		})
		assert.NotContains(t, result, "scope=")
	})

	t.Run("no resource", func(t *testing.T) {
		t.Parallel()
		result := buildAuthorizationURL("https://auth.example.com/authorize", &authorizationURLParams{
			ClientID:            "client-id",
			RedirectURI:         "https://example.com/callback",
			State:               "state-123",
			CodeChallenge:       "challenge",
			CodeChallengeMethod: "S256",
		})
		assert.NotContains(t, result, "resource=")
	})

	t.Run("endpoint with existing query params", func(t *testing.T) {
		t.Parallel()
		result := buildAuthorizationURL("https://auth.example.com/authorize?tenant=abc", &authorizationURLParams{
			ClientID:            "client-id",
			RedirectURI:         "https://example.com/callback",
			State:               "state-123",
			CodeChallenge:       "challenge",
			CodeChallengeMethod: "S256",
		})
		assert.Contains(t, result, "tenant=abc")
		assert.Contains(t, result, "client_id=client-id")
		assert.Contains(t, result, "state=state-123")
		// Must not have double '?' characters
		assert.Equal(t, 1, strings.Count(result, "?"), "URL should have exactly one '?' separator")
	})
}

func TestBuildCallbackURL(t *testing.T) {
	t.Parallel()

	result := buildCallbackURL("proxy.example.com")
	assert.Equal(t, "https://proxy.example.com/.pomerium/mcp/client/oauth/callback", result)
}

func TestBuildClientIDURL(t *testing.T) {
	t.Parallel()

	result := buildClientIDURL("proxy.example.com")
	assert.Equal(t, "https://proxy.example.com/.pomerium/mcp/client/metadata.json", result)
}

func TestGeneratePKCE(t *testing.T) {
	t.Parallel()

	verifier, challenge, err := generatePKCE()
	assert.NoError(t, err)
	assert.NotEmpty(t, verifier)
	assert.NotEmpty(t, challenge)
	assert.NotEqual(t, verifier, challenge)

	// Verify uniqueness
	v2, c2, err := generatePKCE()
	assert.NoError(t, err)
	assert.NotEqual(t, verifier, v2)
	assert.NotEqual(t, challenge, c2)
}

func TestGenerateRandomString(t *testing.T) {
	t.Parallel()

	s1, err := generateRandomString(32)
	assert.NoError(t, err)
	assert.NotEmpty(t, s1)

	s2, err := generateRandomString(32)
	assert.NoError(t, err)
	assert.NotEqual(t, s1, s2)
}

func TestStripPort(t *testing.T) {
	t.Parallel()

	tests := []struct {
		input    string
		expected string
	}{
		{"example.com:443", "example.com"},
		{"example.com:8080", "example.com"},
		{"example.com", "example.com"},
		{"[::1]:443", "::1"},
		{"localhost", "localhost"},
	}

	for _, tt := range tests {
		assert.Equal(t, tt.expected, stripPort(tt.input), "input: %s", tt.input)
	}
}

func TestStripQueryFromURL(t *testing.T) {
	t.Parallel()

	tests := []struct {
		input    string
		expected string
	}{
		{"https://api.example.com/mcp", "https://api.example.com/mcp"},
		{"https://api.example.com/mcp?foo=bar", "https://api.example.com/mcp"},
		{"https://api.example.com/mcp?foo=bar&baz=qux", "https://api.example.com/mcp"},
		{"https://api.example.com", "https://api.example.com"},
		{"https://api.example.com/", "https://api.example.com/"},
		{"https://api.example.com/mcp#fragment", "https://api.example.com/mcp"},
		{"", ""},
	}

	for _, tt := range tests {
		assert.Equal(t, tt.expected, stripQueryFromURL(tt.input), "input: %q", tt.input)
	}
}

func TestNormalizeResourceURL(t *testing.T) {
	t.Parallel()

	tests := []struct {
		input    string
		expected string
	}{
		{"https://api.example.com", "https://api.example.com"},
		{"https://api.example.com/", "https://api.example.com"},
		{"https://api.example.com///", "https://api.example.com"},
		{"https://api.example.com/mcp", "https://api.example.com/mcp"},
		{"https://api.example.com/mcp/", "https://api.example.com/mcp"},
		{"", ""},
	}

	for _, tt := range tests {
		assert.Equal(t, tt.expected, normalizeResourceURL(tt.input), "input: %q", tt.input)
	}
}

// allowLocalhost creates a DomainMatcher that allows 127.0.0.1 for use with httptest servers.
func allowLocalhost() *DomainMatcher {
	return NewDomainMatcher([]string{"127.0.0.1"})
}

func TestRunDiscovery_ResourceValidation(t *testing.T) {
	t.Parallel()

	t.Run("matching resource passes validation", func(t *testing.T) {
		t.Parallel()

		var srvURL string
		srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			switch r.URL.Path {
			case "/.well-known/oauth-protected-resource":
				json.NewEncoder(w).Encode(ProtectedResourceMetadata{
					Resource:             srvURL,
					AuthorizationServers: []string{srvURL + "/oauth"},
				})
			case "/.well-known/oauth-authorization-server/oauth":
				json.NewEncoder(w).Encode(AuthorizationServerMetadata{
					Issuer:                        srvURL + "/oauth",
					AuthorizationEndpoint:         srvURL + "/oauth/authorize",
					TokenEndpoint:                 srvURL + "/oauth/token",
					ResponseTypesSupported:        []string{"code"},
					GrantTypesSupported:           []string{"authorization_code"},
					CodeChallengeMethodsSupported: []string{"S256"},
				})
			default:
				w.WriteHeader(http.StatusNotFound)
			}
		}))
		defer srv.Close()
		srvURL = srv.URL

		result, err := runDiscovery(context.Background(), srv.Client(), nil, srv.URL, "", allowLocalhost())
		require.NoError(t, err)
		assert.Equal(t, srv.URL+"/oauth/authorize", result.AuthorizationEndpoint)
		assert.Equal(t, srv.URL+"/oauth/token", result.TokenEndpoint)
		// PRM path: Resource comes from PRM document
		assert.Equal(t, srvURL, result.Resource)
	})

	t.Run("matching resource with trailing slash difference passes", func(t *testing.T) {
		t.Parallel()

		var srvURL string
		srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			switch r.URL.Path {
			case "/.well-known/oauth-protected-resource":
				// PRM has trailing slash, upstream server URL does not
				json.NewEncoder(w).Encode(ProtectedResourceMetadata{
					Resource:             srvURL + "/",
					AuthorizationServers: []string{srvURL + "/oauth"},
				})
			case "/.well-known/oauth-authorization-server/oauth":
				json.NewEncoder(w).Encode(AuthorizationServerMetadata{
					Issuer:                        srvURL + "/oauth",
					AuthorizationEndpoint:         srvURL + "/oauth/authorize",
					TokenEndpoint:                 srvURL + "/oauth/token",
					ResponseTypesSupported:        []string{"code"},
					GrantTypesSupported:           []string{"authorization_code"},
					CodeChallengeMethodsSupported: []string{"S256"},
				})
			default:
				w.WriteHeader(http.StatusNotFound)
			}
		}))
		defer srv.Close()
		srvURL = srv.URL

		result, err := runDiscovery(context.Background(), srv.Client(), nil, srv.URL, "", allowLocalhost())
		require.NoError(t, err)
		assert.Equal(t, srv.URL+"/oauth/token", result.TokenEndpoint)
		// PRM path: Resource comes from PRM document (with trailing slash)
		assert.Equal(t, srvURL+"/", result.Resource)
	})

	t.Run("origin-level PRM resource matches subpath upstream via path-prefix", func(t *testing.T) {
		t.Parallel()

		var srvURL string
		srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			switch r.URL.Path {
			case "/.well-known/oauth-protected-resource":
				json.NewEncoder(w).Encode(ProtectedResourceMetadata{
					Resource:             srvURL,
					AuthorizationServers: []string{srvURL + "/oauth"},
				})
			case "/.well-known/oauth-authorization-server/oauth":
				json.NewEncoder(w).Encode(AuthorizationServerMetadata{
					Issuer:                        srvURL + "/oauth",
					AuthorizationEndpoint:         srvURL + "/oauth/authorize",
					TokenEndpoint:                 srvURL + "/oauth/token",
					ResponseTypesSupported:        []string{"code"},
					GrantTypesSupported:           []string{"authorization_code"},
					CodeChallengeMethodsSupported: []string{"S256"},
				})
			default:
				w.WriteHeader(http.StatusNotFound)
			}
		}))
		defer srv.Close()
		srvURL = srv.URL

		result, err := runDiscovery(context.Background(), srv.Client(), nil, srv.URL+"/mcp", "", allowLocalhost())
		require.NoError(t, err)
		assert.Equal(t, srv.URL+"/oauth/token", result.TokenEndpoint)
		assert.Equal(t, srvURL, result.Resource)
	})

	t.Run("mismatched resource fails validation", func(t *testing.T) {
		t.Parallel()

		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			switch {
			case r.URL.Path == "/.well-known/oauth-protected-resource":
				// PRM claims to be for a different resource
				json.NewEncoder(w).Encode(ProtectedResourceMetadata{
					Resource:             "https://evil.example.com/mcp",
					AuthorizationServers: []string{"https://evil.example.com/oauth"},
				})
			default:
				w.WriteHeader(http.StatusNotFound)
			}
		}))
		defer srv.Close()

		_, err := runDiscovery(context.Background(), srv.Client(), nil, srv.URL, "", nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "does not match upstream server")
	})

	t.Run("www-authenticate resource_metadata rejects http scheme", func(t *testing.T) {
		t.Parallel()

		wwwAuth := &WWWAuthenticateParams{
			ResourceMetadata: "http://trusted.example.com/.well-known/oauth-protected-resource",
		}
		matcher := NewDomainMatcher([]string{"trusted.example.com"})
		_, err := runDiscovery(context.Background(), &http.Client{}, wwwAuth, "https://real.example.com", "", matcher)
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrSSRFBlocked)
	})

	t.Run("www-authenticate resource_metadata blocked by domain allowlist", func(t *testing.T) {
		t.Parallel()

		// Domain matcher that does NOT allow the test server's domain
		matcher := NewDomainMatcher([]string{"trusted.example.com"})
		wwwAuth := &WWWAuthenticateParams{
			ResourceMetadata: "https://evil.example.com/.well-known/oauth-protected-resource",
		}
		_, err := runDiscovery(context.Background(), &http.Client{}, wwwAuth, "https://real.example.com", "", matcher)
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrDomainNotAllowed)
	})

	t.Run("www-authenticate resource_metadata blocked when no domain matcher configured", func(t *testing.T) {
		t.Parallel()

		wwwAuth := &WWWAuthenticateParams{
			ResourceMetadata: "https://evil.example.com/.well-known/oauth-protected-resource",
		}
		_, err := runDiscovery(context.Background(), &http.Client{}, wwwAuth, "https://real.example.com", "", nil)
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrDomainNotAllowed)
	})

	t.Run("authorization_servers URL from PRM blocked by domain allowlist", func(t *testing.T) {
		t.Parallel()

		// PRM returns an authorization_servers URL on an untrusted domain.
		// The PRM itself is fetched from a well-known URL (no domain check needed),
		// but the AS URL it contains must be validated.
		var srvURL string
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			switch r.URL.Path {
			case "/.well-known/oauth-protected-resource":
				json.NewEncoder(w).Encode(ProtectedResourceMetadata{
					Resource:             srvURL,
					AuthorizationServers: []string{"https://evil.example.com/oauth"},
				})
			default:
				w.WriteHeader(http.StatusNotFound)
			}
		}))
		defer srv.Close()
		srvURL = srv.URL

		matcher := NewDomainMatcher([]string{"trusted.example.com"})
		_, err := runDiscovery(context.Background(), srv.Client(), nil, srv.URL, "", matcher)
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrDomainNotAllowed)
	})

	t.Run("auto-fallback to upstream origin AS metadata when PRM unavailable", func(t *testing.T) {
		t.Parallel()

		// Server serves AS metadata at its own origin but no PRM
		var srvURL string
		srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			switch r.URL.Path {
			case "/.well-known/oauth-authorization-server":
				json.NewEncoder(w).Encode(AuthorizationServerMetadata{
					Issuer:                        srvURL,
					AuthorizationEndpoint:         srvURL + "/authorize",
					TokenEndpoint:                 srvURL + "/token",
					ResponseTypesSupported:        []string{"code"},
					GrantTypesSupported:           []string{"authorization_code"},
					CodeChallengeMethodsSupported: []string{"S256"},
					RegistrationEndpoint:          srvURL + "/register",
				})
			default:
				w.WriteHeader(http.StatusNotFound)
			}
		}))
		defer srv.Close()
		srvURL = srv.URL

		// No explicit override — should auto-derive from upstream origin
		result, err := runDiscovery(context.Background(), srv.Client(), nil, srv.URL+"/mcp", "", allowLocalhost())
		require.NoError(t, err)
		assert.Equal(t, srv.URL+"/authorize", result.AuthorizationEndpoint)
		assert.Equal(t, srv.URL+"/token", result.TokenEndpoint)
		assert.Empty(t, result.ScopesSupported)
		// Fallback path: Resource is the origin (without /mcp path)
		assert.Equal(t, srv.URL, result.Resource)
	})

	t.Run("explicit override AS URL takes precedence over upstream origin", func(t *testing.T) {
		t.Parallel()

		// AS on a different domain than the upstream server
		var asURL string
		asSrv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			switch r.URL.Path {
			case "/.well-known/oauth-authorization-server":
				json.NewEncoder(w).Encode(AuthorizationServerMetadata{
					Issuer:                        asURL,
					AuthorizationEndpoint:         asURL + "/authorize",
					TokenEndpoint:                 asURL + "/token",
					ResponseTypesSupported:        []string{"code"},
					GrantTypesSupported:           []string{"authorization_code"},
					CodeChallengeMethodsSupported: []string{"S256"},
				})
			default:
				w.WriteHeader(http.StatusNotFound)
			}
		}))
		defer asSrv.Close()
		asURL = asSrv.URL

		// Upstream server returns 404 for everything (PRM and AS metadata)
		upstreamSrv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusNotFound)
		}))
		defer upstreamSrv.Close()

		// With explicit override, uses the configured AS URL
		result, err := runDiscovery(context.Background(), asSrv.Client(), nil, upstreamSrv.URL, asSrv.URL, allowLocalhost())
		require.NoError(t, err)
		assert.Equal(t, asSrv.URL+"/authorize", result.AuthorizationEndpoint)
		assert.Equal(t, asSrv.URL+"/token", result.TokenEndpoint)
		// Fallback path: Resource is the origin of the upstream server
		assert.Equal(t, upstreamSrv.URL, result.Resource)
	})
}

func TestRunUpstreamOAuthSetup(t *testing.T) {
	t.Parallel()

	t.Run("success with CIMD", func(t *testing.T) {
		t.Parallel()

		var srvURL string
		srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			switch r.URL.Path {
			case "/.well-known/oauth-protected-resource":
				json.NewEncoder(w).Encode(ProtectedResourceMetadata{
					Resource:             srvURL,
					AuthorizationServers: []string{srvURL + "/oauth"},
				})
			case "/.well-known/oauth-authorization-server/oauth":
				json.NewEncoder(w).Encode(AuthorizationServerMetadata{
					Issuer:                            srvURL + "/oauth",
					AuthorizationEndpoint:             srvURL + "/oauth/authorize",
					TokenEndpoint:                     srvURL + "/oauth/token",
					ResponseTypesSupported:            []string{"code"},
					GrantTypesSupported:               []string{"authorization_code"},
					CodeChallengeMethodsSupported:     []string{"S256"},
					ClientIDMetadataDocumentSupported: true,
				})
			default:
				w.WriteHeader(http.StatusNotFound)
			}
		}))
		defer srv.Close()
		srvURL = srv.URL

		result, err := runUpstreamOAuthSetup(context.Background(), srv.Client(), srvURL, "proxy.example.com",
			WithASMetadataDomainMatcher(allowLocalhost()),
		)
		require.NoError(t, err)
		require.NotNil(t, result)
		assert.Contains(t, result.ClientID, "proxy.example.com")
		assert.Contains(t, result.ClientID, "metadata.json")
		assert.Contains(t, result.RedirectURI, "proxy.example.com")
		assert.Equal(t, srvURL+"/oauth/authorize", result.Discovery.AuthorizationEndpoint)
		assert.Equal(t, srvURL+"/oauth/token", result.Discovery.TokenEndpoint)
	})

	t.Run("no PRM returns error", func(t *testing.T) {
		t.Parallel()

		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusNotFound)
		}))
		defer srv.Close()

		result, err := runUpstreamOAuthSetup(context.Background(), srv.Client(), srv.URL, "proxy.example.com")
		require.Error(t, err)
		assert.Nil(t, result)
	})

	t.Run("CIMD not supported returns error", func(t *testing.T) {
		t.Parallel()

		var srvURL string
		srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			switch r.URL.Path {
			case "/.well-known/oauth-protected-resource":
				json.NewEncoder(w).Encode(ProtectedResourceMetadata{
					Resource:             srvURL,
					AuthorizationServers: []string{srvURL + "/oauth"},
				})
			case "/.well-known/oauth-authorization-server/oauth":
				json.NewEncoder(w).Encode(AuthorizationServerMetadata{
					Issuer:                            srvURL + "/oauth",
					AuthorizationEndpoint:             srvURL + "/oauth/authorize",
					TokenEndpoint:                     srvURL + "/oauth/token",
					ResponseTypesSupported:            []string{"code"},
					GrantTypesSupported:               []string{"authorization_code"},
					CodeChallengeMethodsSupported:     []string{"S256"},
					ClientIDMetadataDocumentSupported: false,
				})
			default:
				w.WriteHeader(http.StatusNotFound)
			}
		}))
		defer srv.Close()
		srvURL = srv.URL

		result, err := runUpstreamOAuthSetup(context.Background(), srv.Client(), srvURL, "proxy.example.com",
			WithASMetadataDomainMatcher(allowLocalhost()),
		)
		require.Error(t, err)
		assert.Nil(t, result)
		assert.Contains(t, err.Error(), "does not support")
	})

	t.Run("with WWW-Authenticate scopes", func(t *testing.T) {
		t.Parallel()

		var srvURL string
		srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			switch r.URL.Path {
			case "/.well-known/oauth-protected-resource":
				json.NewEncoder(w).Encode(ProtectedResourceMetadata{
					Resource:             srvURL,
					AuthorizationServers: []string{srvURL + "/oauth"},
					ScopesSupported:      []string{"read", "write"},
				})
			case "/.well-known/oauth-authorization-server/oauth":
				json.NewEncoder(w).Encode(AuthorizationServerMetadata{
					Issuer:                            srvURL + "/oauth",
					AuthorizationEndpoint:             srvURL + "/oauth/authorize",
					TokenEndpoint:                     srvURL + "/oauth/token",
					ResponseTypesSupported:            []string{"code"},
					GrantTypesSupported:               []string{"authorization_code"},
					CodeChallengeMethodsSupported:     []string{"S256"},
					ClientIDMetadataDocumentSupported: true,
				})
			default:
				w.WriteHeader(http.StatusNotFound)
			}
		}))
		defer srv.Close()
		srvURL = srv.URL

		result, err := runUpstreamOAuthSetup(context.Background(), srv.Client(), srvURL, "proxy.example.com",
			WithWWWAuthenticate(&WWWAuthenticateParams{Scope: []string{"admin"}}),
			WithASMetadataDomainMatcher(allowLocalhost()),
		)
		require.NoError(t, err)
		require.NotNil(t, result)
		assert.Equal(t, []string{"admin"}, result.Scopes, "WWW-Authenticate scopes should take priority")
	})

	t.Run("PRM path-prefix match accepts parent resource", func(t *testing.T) {
		t.Parallel()

		var srvURL string
		srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			switch r.URL.Path {
			case "/.well-known/oauth-protected-resource/mcp":
				json.NewEncoder(w).Encode(ProtectedResourceMetadata{
					Resource:             srvURL,
					AuthorizationServers: []string{srvURL + "/oauth"},
				})
			case "/.well-known/oauth-authorization-server/oauth":
				json.NewEncoder(w).Encode(AuthorizationServerMetadata{
					Issuer:                            srvURL + "/oauth",
					AuthorizationEndpoint:             srvURL + "/oauth/authorize",
					TokenEndpoint:                     srvURL + "/oauth/token",
					ResponseTypesSupported:            []string{"code"},
					GrantTypesSupported:               []string{"authorization_code"},
					CodeChallengeMethodsSupported:     []string{"S256"},
					ClientIDMetadataDocumentSupported: true,
				})
			default:
				w.WriteHeader(http.StatusNotFound)
			}
		}))
		defer srv.Close()
		srvURL = srv.URL

		// Origin-level PRM resource should match subpath upstream via path-prefix
		result, err := runUpstreamOAuthSetup(context.Background(), srv.Client(), srvURL+"/mcp", "proxy.example.com",
			WithASMetadataDomainMatcher(allowLocalhost()),
		)
		require.NoError(t, err)
		require.NotNil(t, result)
		assert.Equal(t, srvURL+"/oauth/token", result.Discovery.TokenEndpoint)
		assert.Equal(t, srvURL, result.Discovery.Resource)
	})

	t.Run("PRM path-prefix rejects non-prefix paths", func(t *testing.T) {
		t.Parallel()

		var srvURL string
		srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			switch r.URL.Path {
			case "/.well-known/oauth-protected-resource/admin":
				// PRM resource is /api but upstream is /admin — not a prefix match
				json.NewEncoder(w).Encode(ProtectedResourceMetadata{
					Resource:             srvURL + "/api",
					AuthorizationServers: []string{srvURL + "/oauth"},
				})
			default:
				w.WriteHeader(http.StatusNotFound)
			}
		}))
		defer srv.Close()
		srvURL = srv.URL

		result, err := runUpstreamOAuthSetup(context.Background(), srv.Client(), srvURL+"/admin", "proxy.example.com",
			WithASMetadataDomainMatcher(allowLocalhost()),
		)
		require.Error(t, err)
		assert.Nil(t, result)
		assert.Contains(t, err.Error(), "does not match")
	})
}

func TestCheckResourceAllowed(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name              string
		upstreamServerURL string
		prmResource       string
		expectAllowed     bool
		expectError       bool
	}{
		{
			name:              "identical URLs",
			upstreamServerURL: "https://api.example.com/v1",
			prmResource:       "https://api.example.com/v1",
			expectAllowed:     true,
		},
		{
			name:              "origin-level resource matches subpath",
			upstreamServerURL: "https://mcp.example.com/mcp",
			prmResource:       "https://mcp.example.com",
			expectAllowed:     true,
		},
		{
			name:              "origin-level resource matches root",
			upstreamServerURL: "https://mcp.example.com",
			prmResource:       "https://mcp.example.com",
			expectAllowed:     true,
		},
		{
			name:              "subpath matches parent",
			upstreamServerURL: "https://api.example.com/api/v1",
			prmResource:       "https://api.example.com/api",
			expectAllowed:     true,
		},
		{
			name:              "non-prefix path rejects",
			upstreamServerURL: "https://example.com/admin",
			prmResource:       "https://example.com/api",
			expectAllowed:     false,
		},
		{
			name:              "non-prefix similar name rejects",
			upstreamServerURL: "https://example.com/mcpxxxx",
			prmResource:       "https://example.com/mcp",
			expectAllowed:     false,
		},
		{
			name:              "different scheme rejects",
			upstreamServerURL: "https://example.com/path",
			prmResource:       "http://example.com/path",
			expectAllowed:     false,
		},
		{
			name:              "different host rejects",
			upstreamServerURL: "https://a.example.com/path",
			prmResource:       "https://b.example.com/path",
			expectAllowed:     false,
		},
		{
			name:              "different port rejects",
			upstreamServerURL: "https://example.com:8443/path",
			prmResource:       "https://example.com:9443/path",
			expectAllowed:     false,
		},
		{
			name:              "trailing slash normalization",
			upstreamServerURL: "https://example.com/api/",
			prmResource:       "https://example.com/api",
			expectAllowed:     true,
		},
		{
			name:              "resource child path rejects parent upstream",
			upstreamServerURL: "https://example.com/",
			prmResource:       "https://example.com/path",
			expectAllowed:     false,
		},
		{
			name:              "resource trailing slash matches after path normalization",
			upstreamServerURL: "https://example.com/folder",
			prmResource:       "https://example.com/folder/",
			expectAllowed:     true,
		},
		{
			name:              "invalid upstream URL",
			upstreamServerURL: "://invalid",
			prmResource:       "https://example.com",
			expectError:       true,
		},
		{
			name:              "invalid PRM resource URL",
			upstreamServerURL: "https://example.com",
			prmResource:       "://invalid",
			expectError:       true,
		},
		{
			name:              "empty upstream URL",
			upstreamServerURL: "",
			prmResource:       "https://example.com",
			expectError:       true,
		},
		{
			name:              "empty PRM resource URL",
			upstreamServerURL: "https://example.com",
			prmResource:       "",
			expectError:       true,
		},
		{
			name:              "relative upstream URL",
			upstreamServerURL: "/just/a/path",
			prmResource:       "https://example.com",
			expectError:       true,
		},
		{
			name:              "relative PRM resource URL",
			upstreamServerURL: "https://example.com",
			prmResource:       "/just/a/path",
			expectError:       true,
		},
		{
			name:              "path traversal in upstream does not bypass prefix check",
			upstreamServerURL: "https://example.com/api/../admin",
			prmResource:       "https://example.com/api",
			expectAllowed:     false,
		},
		{
			name:              "case-insensitive host comparison",
			upstreamServerURL: "https://Example.Com/path",
			prmResource:       "https://example.com/path",
			expectAllowed:     true,
		},
		{
			name:              "case-insensitive scheme comparison",
			upstreamServerURL: "HTTPS://example.com/path",
			prmResource:       "https://example.com/path",
			expectAllowed:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			allowed, err := checkResourceAllowed(tt.upstreamServerURL, tt.prmResource)
			if tt.expectError {
				assert.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.expectAllowed, allowed)
			}
		})
	}
}

// TestOriginOf verifies the originOf helper function used to derive the resource identifier
// in the fallback AS discovery path.
func TestOriginOf(t *testing.T) {
	t.Parallel()

	t.Run("success cases", func(t *testing.T) {
		t.Parallel()
		tests := []struct {
			name     string
			input    string
			expected string
		}{
			{
				name:     "standard URL strips path",
				input:    "https://api.example.com/mcp/tools/list",
				expected: "https://api.example.com",
			},
			{
				name:     "URL with port preserved",
				input:    "https://api.example.com:8443/mcp",
				expected: "https://api.example.com:8443",
			},
			{
				name:     "URL with query and fragment stripped",
				input:    "https://api.example.com/path?foo=bar#section",
				expected: "https://api.example.com",
			},
			{
				name:     "bare origin unchanged",
				input:    "https://api.example.com",
				expected: "https://api.example.com",
			},
			{
				name:     "HTTP scheme preserved",
				input:    "http://localhost:8080/mcp",
				expected: "http://localhost:8080",
			},
			{
				name:     "trailing slash stripped",
				input:    "https://api.example.com/",
				expected: "https://api.example.com",
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				t.Parallel()
				result, err := originOf(tt.input)
				require.NoError(t, err)
				assert.Equal(t, tt.expected, result)
			})
		}
	})

	t.Run("error cases", func(t *testing.T) {
		t.Parallel()
		tests := []struct {
			name  string
			input string
		}{
			{name: "empty string", input: ""},
			{name: "missing scheme", input: "api.example.com/path"},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				t.Parallel()
				_, err := originOf(tt.input)
				assert.Error(t, err)
			})
		}
	})
}
