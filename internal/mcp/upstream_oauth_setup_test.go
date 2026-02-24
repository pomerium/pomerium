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
		assert.Equal(t, srv.URL+"/register", result.RegistrationEndpoint)
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

func TestRegisterWithUpstreamAS(t *testing.T) {
	t.Parallel()

	t.Run("successful registration", func(t *testing.T) {
		t.Parallel()

		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, http.MethodPost, r.Method)
			assert.Equal(t, "application/json", r.Header.Get("Content-Type"))

			var body map[string]any
			require.NoError(t, json.NewDecoder(r.Body).Decode(&body))
			assert.Equal(t, "Test Client", body["client_name"])
			assert.Equal(t, []any{"https://proxy.example.com/callback"}, body["redirect_uris"])
			assert.Equal(t, []any{"authorization_code"}, body["grant_types"])
			assert.Equal(t, "none", body["token_endpoint_auth_method"])

			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusCreated)
			json.NewEncoder(w).Encode(map[string]any{
				"client_id":                "new-client-id",
				"client_secret":            "new-client-secret",
				"client_secret_expires_at": 0,
			})
		}))
		defer srv.Close()

		clientID, clientSecret, err := registerWithUpstreamAS(
			context.Background(), srv.Client(),
			srv.URL, "https://proxy.example.com/callback", "Test Client",
		)
		require.NoError(t, err)
		assert.Equal(t, "new-client-id", clientID)
		assert.Equal(t, "new-client-secret", clientSecret)
	})

	t.Run("registration returns 400", func(t *testing.T) {
		t.Parallel()

		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte(`{"error": "invalid_client_metadata"}`))
		}))
		defer srv.Close()

		_, _, err := registerWithUpstreamAS(
			context.Background(), srv.Client(),
			srv.URL, "https://proxy.example.com/callback", "Test Client",
		)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "registration endpoint returned 400")
	})

	t.Run("response missing client_id", func(t *testing.T) {
		t.Parallel()

		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusCreated)
			json.NewEncoder(w).Encode(map[string]any{
				"client_secret":            "secret-only",
				"client_secret_expires_at": 0,
			})
		}))
		defer srv.Close()

		_, _, err := registerWithUpstreamAS(
			context.Background(), srv.Client(),
			srv.URL, "https://proxy.example.com/callback", "Test Client",
		)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "client_id")
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
		assert.Empty(t, result.ClientSecret)
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

	t.Run("DCR fallback", func(t *testing.T) {
		t.Parallel()

		dcrSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodPost {
				w.WriteHeader(http.StatusMethodNotAllowed)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusCreated)
			json.NewEncoder(w).Encode(map[string]any{
				"client_id":                "dcr-client",
				"client_secret":            "dcr-secret",
				"client_secret_expires_at": 0,
			})
		}))
		defer dcrSrv.Close()

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
					RegistrationEndpoint:              dcrSrv.URL + "/register",
				})
			default:
				w.WriteHeader(http.StatusNotFound)
			}
		}))
		defer srv.Close()
		srvURL = srv.URL

		// Use the TLS server's client that trusts its self-signed cert
		result, err := runUpstreamOAuthSetup(context.Background(), srv.Client(), srvURL, "proxy.example.com",
			WithASMetadataDomainMatcher(allowLocalhost()),
		)
		require.NoError(t, err)
		require.NotNil(t, result)
		assert.Equal(t, "dcr-client", result.ClientID)
		assert.Equal(t, "dcr-secret", result.ClientSecret)
	})

	t.Run("neither CIMD nor DCR returns error", func(t *testing.T) {
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
					// No registration_endpoint
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
