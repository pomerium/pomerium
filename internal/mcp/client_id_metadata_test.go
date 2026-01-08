package mcp

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
			name:        "contains query string - RFC violation",
			clientID:    "https://example.com/oauth/client.json?foo=bar",
			expectIsURL: false,
			expectError: true,
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

		fetcher := NewClientMetadataFetcher(server.Client())
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
		fetcher := NewClientMetadataFetcher(server.Client())
		_, err := fetcher.Fetch(context.Background(), clientIDURL)
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrClientMetadataValidation)
		assert.Contains(t, err.Error(), "does not match URL")
	})

	t.Run("rejects when redirect_uris is missing", func(t *testing.T) {
		clientIDURL := ""
		server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			metadata := map[string]any{
				"client_id":                  clientIDURL,
				"client_name":                "Test Client",
				"token_endpoint_auth_method": "none",
				// redirect_uris is missing
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(metadata)
		}))
		defer server.Close()

		clientIDURL = server.URL + "/oauth/client.json"
		server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			metadata := map[string]any{
				"client_id":                  clientIDURL,
				"client_name":                "Test Client",
				"token_endpoint_auth_method": "none",
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(metadata)
		})

		fetcher := NewClientMetadataFetcher(server.Client())
		_, err := fetcher.Fetch(context.Background(), clientIDURL)
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrClientMetadataValidation)
		assert.Contains(t, err.Error(), "redirect_uris is required")
	})

	t.Run("rejects client_secret_basic auth method", func(t *testing.T) {
		clientIDURL := ""
		server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			metadata := map[string]any{
				"client_id":                  clientIDURL,
				"client_name":                "Test Client",
				"redirect_uris":              []string{"http://localhost:8080/callback"},
				"token_endpoint_auth_method": "client_secret_basic",
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(metadata)
		}))
		defer server.Close()

		clientIDURL = server.URL + "/oauth/client.json"
		server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			metadata := map[string]any{
				"client_id":                  clientIDURL,
				"client_name":                "Test Client",
				"redirect_uris":              []string{"http://localhost:8080/callback"},
				"token_endpoint_auth_method": "client_secret_basic",
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(metadata)
		})

		fetcher := NewClientMetadataFetcher(server.Client())
		_, err := fetcher.Fetch(context.Background(), clientIDURL)
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrClientMetadataValidation)
		assert.Contains(t, err.Error(), "not allowed")
	})

	t.Run("rejects HTTP 404", func(t *testing.T) {
		server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusNotFound)
		}))
		defer server.Close()

		clientIDURL := server.URL + "/oauth/nonexistent.json"
		fetcher := NewClientMetadataFetcher(server.Client())
		_, err := fetcher.Fetch(context.Background(), clientIDURL)
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrClientMetadataFetch)
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
