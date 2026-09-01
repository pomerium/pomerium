package mcp

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-jose/go-jose/v3"
	"github.com/go-jose/go-jose/v3/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	rfc7591v1 "github.com/pomerium/pomerium/internal/rfc7591"
)

func TestIsClientIDMetadataURL(t *testing.T) {
	tests := []struct {
		name        string
		clientID    string
		expectIsURL bool
		expectError bool
	}{
		{
			name:        "valid HTTPS URL with path",
			clientID:    "https://example.com/oauth/client.json",
			expectIsURL: true,
			expectError: false,
		},
		{
			name:        "valid HTTPS URL with nested path",
			clientID:    "https://example.com/oauth/clients/app.json",
			expectIsURL: true,
			expectError: false,
		},
		{
			name:        "valid HTTPS URL with port",
			clientID:    "https://example.com:8443/oauth/client.json",
			expectIsURL: true,
			expectError: false,
		},
		{
			name:        "HTTP scheme - not a metadata URL",
			clientID:    "http://example.com/oauth/client.json",
			expectIsURL: false,
			expectError: false, // Not an error, just not a metadata URL
		},
		{
			name:        "no path component - RFC violation",
			clientID:    "https://example.com",
			expectIsURL: false,
			expectError: true,
		},
		{
			name:        "only root path - RFC violation",
			clientID:    "https://example.com/",
			expectIsURL: false,
			expectError: true,
		},
		{
			name:        "contains fragment - RFC violation",
			clientID:    "https://example.com/oauth/client.json#section",
			expectIsURL: false,
			expectError: true,
		},
		{
			name:        "contains username - RFC violation",
			clientID:    "https://user@example.com/oauth/client.json",
			expectIsURL: false,
			expectError: true,
		},
		{
			name:        "contains single dot path segment - RFC violation",
			clientID:    "https://example.com/./oauth/client.json",
			expectIsURL: false,
			expectError: true,
		},
		{
			name:        "contains double dot path segment - RFC violation",
			clientID:    "https://example.com/../oauth/client.json",
			expectIsURL: false,
			expectError: true,
		},
		{
			name:        "contains query string - tolerated (RFC SHOULD NOT)",
			clientID:    "https://example.com/oauth/client.json?foo=bar",
			expectIsURL: true,
			expectError: false,
		},
		{
			name:        "real-world client_id URL with query string",
			clientID:    "https://chatgpt.com/oauth/XXXXXXXXXX/client.json?token_endpoint_auth_method=none",
			expectIsURL: true,
			expectError: false,
		},
		{
			name:        "UUID-style client ID - not a URL",
			clientID:    "550e8400-e29b-41d4-a716-446655440000",
			expectIsURL: false,
			expectError: false,
		},
		{
			name:        "empty string - not a URL",
			clientID:    "",
			expectIsURL: false,
			expectError: false,
		},
		{
			name:        "relative path - not a URL",
			clientID:    "/oauth/client.json",
			expectIsURL: false,
			expectError: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			isURL, err := IsClientIDMetadataURL(tc.clientID)
			assert.Equal(t, tc.expectIsURL, isURL)
			if tc.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// allowAllDomainMatcher creates a domain matcher that allows 127.0.0.1 for test servers.
func allowAllDomainMatcher() *DomainMatcher {
	return NewDomainMatcher([]string{"127.0.0.1"})
}

func TestClientMetadataFetcher_Fetch(t *testing.T) {
	t.Run("successfully fetches valid metadata", func(t *testing.T) {
		server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			metadata := map[string]any{
				"client_id":                  "", // Will be set dynamically
				"client_name":                "Test Client",
				"redirect_uris":              []string{"http://localhost:8080/callback"},
				"grant_types":                []string{"authorization_code"},
				"response_types":             []string{"code"},
				"token_endpoint_auth_method": "none",
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(metadata)
		}))
		defer server.Close()

		// We need to serve the document with the correct client_id
		clientIDURL := server.URL + "/oauth/client.json"
		server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			metadata := map[string]any{
				"client_id":                  clientIDURL,
				"client_name":                "Test Client",
				"redirect_uris":              []string{"http://localhost:8080/callback"},
				"grant_types":                []string{"authorization_code"},
				"response_types":             []string{"code"},
				"token_endpoint_auth_method": "none",
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(metadata)
		})

		fetcher := NewClientMetadataFetcher(server.Client(), allowAllDomainMatcher())
		doc, err := fetcher.Fetch(context.Background(), clientIDURL)
		require.NoError(t, err)
		assert.Equal(t, clientIDURL, doc.ClientID)
		assert.Equal(t, "Test Client", doc.ClientName)
		assert.Contains(t, doc.RedirectURIs, "http://localhost:8080/callback")
	})

	t.Run("rejects when client_id doesn't match URL", func(t *testing.T) {
		server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			metadata := map[string]any{
				"client_id":                  "https://different-url.example.com/client.json",
				"client_name":                "Test Client",
				"redirect_uris":              []string{"http://localhost:8080/callback"},
				"token_endpoint_auth_method": "none",
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(metadata)
		}))
		defer server.Close()

		clientIDURL := server.URL + "/oauth/client.json"
		fetcher := NewClientMetadataFetcher(server.Client(), allowAllDomainMatcher())
		_, err := fetcher.Fetch(context.Background(), clientIDURL)
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrClientMetadataValidation)
		assert.Contains(t, err.Error(), "does not match URL")
	})

	t.Run("rejects HTTP 404", func(t *testing.T) {
		server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusNotFound)
		}))
		defer server.Close()

		clientIDURL := server.URL + "/oauth/nonexistent.json"
		fetcher := NewClientMetadataFetcher(server.Client(), allowAllDomainMatcher())
		_, err := fetcher.Fetch(context.Background(), clientIDURL)
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrClientMetadataFetch)
	})

	t.Run("rejects when domain not in allowed list", func(t *testing.T) {
		// Domain matcher that only allows vscode.dev
		matcher := NewDomainMatcher([]string{"vscode.dev"})
		fetcher := NewClientMetadataFetcher(http.DefaultClient, matcher)

		_, err := fetcher.Fetch(context.Background(), "https://evil.com/oauth/client.json")
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrClientMetadataValidation)
		assert.ErrorIs(t, err, ErrDomainNotAllowed)
		assert.Contains(t, err.Error(), "not in allowed domains")
	})

	t.Run("rejects when no domains configured", func(t *testing.T) {
		fetcher := NewClientMetadataFetcher(http.DefaultClient, nil)

		_, err := fetcher.Fetch(context.Background(), "https://any.com/oauth/client.json")
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrDomainNotAllowed)
		assert.Contains(t, err.Error(), "no allowed domains configured")
	})
}

func TestClientIDMetadataDocument_ValidateRedirectURI(t *testing.T) {
	doc := &ClientIDMetadataDocument{
		ClientID:     "https://example.com/oauth/client.json",
		RedirectURIs: []string{"http://localhost:8080/callback", "http://127.0.0.1:3000/cb"},
	}

	t.Run("valid redirect URI", func(t *testing.T) {
		err := doc.ValidateRedirectURI("http://localhost:8080/callback")
		assert.NoError(t, err)
	})

	t.Run("another valid redirect URI", func(t *testing.T) {
		err := doc.ValidateRedirectURI("http://127.0.0.1:3000/cb")
		assert.NoError(t, err)
	})

	t.Run("invalid redirect URI", func(t *testing.T) {
		err := doc.ValidateRedirectURI("http://evil.com/callback")
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrClientMetadataValidation)
	})
}

func TestClientIDMetadataDocument_ToClientRegistration(t *testing.T) {
	doc := &ClientIDMetadataDocument{
		ClientID:                "https://example.com/oauth/client.json",
		ClientName:              "Test App",
		ClientURI:               "https://example.com",
		RedirectURIs:            []string{"http://localhost:8080/callback"},
		GrantTypes:              []string{"authorization_code"},
		ResponseTypes:           []string{"code"},
		TokenEndpointAuthMethod: "none",
	}

	reg := doc.ToClientRegistration()
	require.NotNil(t, reg)
	require.NotNil(t, reg.ResponseMetadata)

	assert.Equal(t, []string{"http://localhost:8080/callback"}, reg.ResponseMetadata.RedirectUris)
	assert.Equal(t, "Test App", reg.ResponseMetadata.GetClientName())
	assert.Equal(t, "https://example.com", reg.ResponseMetadata.GetClientUri())
	assert.Equal(t, "none", reg.ResponseMetadata.GetTokenEndpointAuthMethod())
	assert.Nil(t, reg.ClientSecret, "client secret should be nil for metadata document clients")
}

func TestClientIDMetadataDocument_Validate(t *testing.T) {
	tcs := []struct {
		name    string
		doc     ClientIDMetadataDocument
		wantErr string
	}{
		{
			name:    "missing redirect_uris",
			doc:     ClientIDMetadataDocument{},
			wantErr: "redirect_uris is required",
		},
		{
			name: "rejects client basic auth",
			doc: ClientIDMetadataDocument{
				RedirectURIs:            []string{"https://client.example.com/callback"},
				TokenEndpointAuthMethod: "client_secret_basic",
			},
			wantErr: "not allowed",
		},

		{
			name: "insecure_jwks_uri",
			doc: ClientIDMetadataDocument{
				RedirectURIs: []string{"https://client.example.com/callback"},
				JWKSURI:      "http://client.example.com/jwks.json",
			},
			wantErr: "must use the https scheme",
		},
		{
			name: "private_key_jwt_without_keys",
			doc: ClientIDMetadataDocument{
				RedirectURIs:            []string{"https://client.example.com/callback"},
				TokenEndpointAuthMethod: "private_key_jwt",
			},
			wantErr: "requires jwks_uri",
		},

		{
			name: "jwks_uri without private_key_jwt",
			doc: ClientIDMetadataDocument{
				RedirectURIs:            []string{"https://client.example.com/callback"},
				JWKSURI:                 "https://client.example.com/jwks.json",
				TokenEndpointAuthMethod: rfc7591v1.TokenEndpointAuthMethodNone,
			},
		},
		{
			name: "valid private_key_jwt",
			doc: ClientIDMetadataDocument{
				RedirectURIs:            []string{"https://client.example.com/callback"},
				TokenEndpointAuthMethod: "private_key_jwt",
				JWKSURI:                 "https://client.example.com/jwks.json",
			},
		},
		{
			name: "valid",
			doc: ClientIDMetadataDocument{
				RedirectURIs: []string{"https://client.example.com/callback"},
			},
		},
	}

	for _, tc := range tcs {
		err := tc.doc.Validate()
		if tc.wantErr != "" {
			assert.ErrorIs(t, err, ErrClientMetadataValidation, tc.name)
			assert.ErrorContains(t, err, tc.wantErr, tc.name)
			continue
		}
		assert.NoError(t, err)
	}
}

func TestJWKSFetcher(t *testing.T) {
	t.Run("fetch successfully", func(t *testing.T) {
		key := newAssertionTestKey(t, jose.RS256, "test-key")
		client, jwksURI := jwksHandler(t, key.jwks())
		assertion := key.sign(t, jwt.Claims{Subject: "test-client"})

		jwks := NewJWKSFetcher(client, allowAllDomainMatcher())
		keySet, err := jwks.KeySet(context.Background(), jwksURI)
		require.NoError(t, err)

		got, err := keySet.VerifySignature(context.Background(), assertion)
		require.NoError(t, err)
		var claims jwt.Claims
		require.NoError(t, json.Unmarshal(got, &claims))
		assert.Equal(t, "test-client", claims.Subject)
	})

	t.Run("fetch invalid key", func(t *testing.T) {
		key := newAssertionTestKey(t, jose.RS256, "test-key")
		invalidKey := newAssertionTestKey(t, jose.RS256, "test-key")
		client, jwksURI := jwksHandler(t, key.jwks())
		assertion := invalidKey.sign(t, jwt.Claims{Subject: "test-client"})

		jwks := NewJWKSFetcher(client, allowAllDomainMatcher())
		keySet, err := jwks.KeySet(context.Background(), jwksURI)
		require.NoError(t, err)

		_, sigErr := keySet.VerifySignature(context.Background(), assertion)
		require.Error(t, sigErr)
		assert.ErrorContains(t, sigErr, "failed to verify")
	})

	t.Run("fetch not found", func(t *testing.T) {
		server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "/jwks.json", r.URL.Path)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusNotFound)
		}))
		defer server.Close()
		jwks := NewJWKSFetcher(server.Client(), allowAllDomainMatcher())
		ks, err := jwks.KeySet(context.Background(), server.URL+"/jwks.json")
		require.NoError(t, err)

		key := newAssertionTestKey(t, jose.RS256, "test-key")
		assertion := key.sign(t, jwt.Claims{Subject: "test-client"})

		_, sigErr := ks.VerifySignature(t.Context(), assertion)
		require.Error(t, sigErr)
		assert.ErrorContains(t, sigErr, "Not Found")
	})

	t.Run("invalid domain", func(t *testing.T) {
		matcher := NewDomainMatcher([]string{"vscode.dev"})
		key := newAssertionTestKey(t, jose.RS256, "test-key")
		client, jwksURI := jwksHandler(t, key.jwks())

		jwks := NewJWKSFetcher(client, matcher)
		_, err := jwks.KeySet(context.Background(), jwksURI)
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrDomainNotAllowed)
	})

	t.Run("no domain matcher", func(t *testing.T) {
		key := newAssertionTestKey(t, jose.RS256, "test-key")
		client, jwksURI := jwksHandler(t, key.jwks())

		jwks := NewJWKSFetcher(client, nil)
		_, err := jwks.KeySet(context.Background(), jwksURI)
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrDomainNotAllowed)
	})
}

type assertionTestKey struct {
	alg        jose.SignatureAlgorithm
	signingKey any
	publicKey  any
	kid        string
}

func newAssertionTestKey(
	t *testing.T,
	alg jose.SignatureAlgorithm,
	kid string,
) assertionTestKey {
	t.Helper()

	switch alg {
	case jose.RS256:
		private, err := rsa.GenerateKey(rand.Reader, 2048)
		require.NoError(t, err)

		return assertionTestKey{
			alg:        alg,
			signingKey: private,
			publicKey:  private.Public(),
			kid:        kid,
		}

	case jose.HS256:
		secret := make([]byte, 32)
		_, err := rand.Read(secret)
		require.NoError(t, err)

		return assertionTestKey{
			alg:        alg,
			signingKey: secret,
			publicKey:  secret,
			kid:        kid,
		}

	default:
		t.Fatalf("unsupported test signing algorithm %q", alg)
		return assertionTestKey{}
	}
}

func (k assertionTestKey) jwks() jose.JSONWebKeySet {
	return jose.JSONWebKeySet{
		Keys: []jose.JSONWebKey{{
			Key:       k.publicKey,
			KeyID:     k.kid,
			Algorithm: string(k.alg),
			Use:       "sig",
		}},
	}
}

func (k assertionTestKey) sign(t *testing.T, claims jwt.Claims) string {
	t.Helper()

	signer, err := jose.NewSigner(
		jose.SigningKey{
			Algorithm: k.alg,
			Key:       k.signingKey,
		},
		(&jose.SignerOptions{}).
			WithHeader(jose.HeaderKey("kid"), k.kid),
	)
	require.NoError(t, err)

	raw, err := jwt.Signed(signer).
		Claims(claims).
		CompactSerialize()
	require.NoError(t, err)
	return raw
}

func jwksHandler(t *testing.T, keys jose.JSONWebKeySet) (client *http.Client, uri string) {
	t.Helper()
	return jwksHandlerFunc(t, keys, nil)
}

// jwksHandlerFunc serves keys over TLS, calling onRequest, if set, per request.
func jwksHandlerFunc(t *testing.T, keys jose.JSONWebKeySet, onRequest func()) (client *http.Client, uri string) {
	t.Helper()
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if onRequest != nil {
			onRequest()
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(keys)
	}))
	t.Cleanup(server.Close)
	return server.Client(), server.URL + "/jwks.json"
}
