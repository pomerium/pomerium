package mcp

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestExchangeToken(t *testing.T) {
	t.Parallel()

	t.Run("successful exchange", func(t *testing.T) {
		t.Parallel()
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{
				"access_token": "at-123",
				"token_type": "Bearer",
				"expires_in": 3600,
				"refresh_token": "rt-456",
				"scope": "read write"
			}`))
		}))
		defer server.Close()

		req, err := http.NewRequest(http.MethodPost, server.URL, nil)
		require.NoError(t, err)

		resp, err := exchangeToken(server.Client(), req)
		require.NoError(t, err)
		assert.Equal(t, "at-123", resp.AccessToken)
		assert.Equal(t, "Bearer", resp.TokenType)
		assert.Equal(t, int64(3600), resp.ExpiresIn)
		assert.Equal(t, "rt-456", resp.RefreshToken)
		assert.Equal(t, "read write", resp.Scope)
	})

	t.Run("non-200 status", func(t *testing.T) {
		t.Parallel()
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"error":"invalid_grant"}`))
		}))
		defer server.Close()

		req, err := http.NewRequest(http.MethodPost, server.URL, nil)
		require.NoError(t, err)

		_, err = exchangeToken(server.Client(), req)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "token endpoint returned 400")
	})

	t.Run("missing access_token", func(t *testing.T) {
		t.Parallel()
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"token_type":"Bearer"}`))
		}))
		defer server.Close()

		req, err := http.NewRequest(http.MethodPost, server.URL, nil)
		require.NoError(t, err)

		_, err = exchangeToken(server.Client(), req)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "missing access_token")
	})

	t.Run("invalid JSON", func(t *testing.T) {
		t.Parallel()
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`not json`))
		}))
		defer server.Close()

		req, err := http.NewRequest(http.MethodPost, server.URL, nil)
		require.NoError(t, err)

		_, err = exchangeToken(server.Client(), req)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "parsing token response")
	})

	t.Run("minimal response", func(t *testing.T) {
		t.Parallel()
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"access_token":"at-min","token_type":"Bearer"}`))
		}))
		defer server.Close()

		req, err := http.NewRequest(http.MethodPost, server.URL, nil)
		require.NoError(t, err)

		resp, err := exchangeToken(server.Client(), req)
		require.NoError(t, err)
		assert.Equal(t, "at-min", resp.AccessToken)
		assert.Equal(t, int64(0), resp.ExpiresIn)
		assert.Empty(t, resp.RefreshToken)
	})
}
