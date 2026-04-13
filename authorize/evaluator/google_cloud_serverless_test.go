package evaluator

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"
)

func withMockGCP(t *testing.T, handler http.HandlerFunc) {
	t.Helper()
	originalGCPIdentityDocURL := GCPIdentityDocURL
	originalNow := GCPIdentityNow

	now := time.Date(2020, 1, 1, 1, 0, 0, 0, time.UTC)
	GCPIdentityNow = func() time.Time {
		return now
	}

	srv := httptest.NewServer(handler)
	GCPIdentityDocURL = srv.URL

	// clear the global token source cache so tests don't interfere
	gcpTokenSources.Lock()
	saved := gcpTokenSources.m
	gcpTokenSources.m = make(map[gcpTokenSourceKey]oauth2.TokenSource)
	gcpTokenSources.Unlock()

	t.Cleanup(func() {
		srv.Close()
		GCPIdentityDocURL = originalGCPIdentityDocURL
		GCPIdentityNow = originalNow
		gcpTokenSources.Lock()
		gcpTokenSources.m = saved
		gcpTokenSources.Unlock()
	})
}

func TestGCPIdentityTokenSource(t *testing.T) {
	// Not parallel: withMockGCP mutates package-level globals
	// (GCPIdentityDocURL, GCPIdentityNow) without synchronization.

	t.Run("success", func(t *testing.T) {
		withMockGCP(t, func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "Google", r.Header.Get("Metadata-Flavor"))
			assert.Equal(t, "full", r.URL.Query().Get("format"))
			_, _ = w.Write([]byte("eyJhbGciOiJSUzI1NiJ9.eyJhdWQiOiJleGFtcGxlIn0.signature"))
		})

		src, err := getGoogleCloudServerlessTokenSource("", "example")
		require.NoError(t, err)

		token, err := src.Token()
		require.NoError(t, err)
		assert.Equal(t, "eyJhbGciOiJSUzI1NiJ9.eyJhdWQiOiJleGFtcGxlIn0.signature", token.AccessToken)
	})

	t.Run("non-200 status returns error", func(t *testing.T) {
		withMockGCP(t, func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte("<!DOCTYPE html><html><body>not found</body></html>"))
		})

		src, err := getGoogleCloudServerlessTokenSource("", "bad-audience")
		require.NoError(t, err)

		token, err := src.Token()
		assert.Nil(t, token)
		assert.ErrorContains(t, err, "metadata identity endpoint returned HTTP 404")
		assert.ErrorContains(t, err, "bad-audience")
	})

	t.Run("empty body returns error", func(t *testing.T) {
		withMockGCP(t, func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
			// write nothing
		})

		src, err := getGoogleCloudServerlessTokenSource("", "empty-response")
		require.NoError(t, err)

		token, err := src.Token()
		assert.Nil(t, token)
		assert.ErrorContains(t, err, "empty token")
	})

	t.Run("non-200 prevents invalid Authorization header", func(t *testing.T) {
		// This is the exact scenario that caused the staging 503:
		// metadata server returns 404, body gets used as Bearer token,
		// Envoy rejects the invalid header value.
		withMockGCP(t, func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte("not found\n"))
		})

		headers, err := getGoogleCloudServerlessHeaders("", "https://example.run.app")
		assert.Error(t, err)
		assert.Nil(t, headers, "must not produce headers with an invalid token")
	})
}

func Test_normalizeServiceAccount(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name                   string
		serviceAccount         string
		expectedServiceAccount string
		wantError              bool
	}{
		{"empty", "", "", false},
		{"leading spaces", `  {"service_account": "foo"}`, `{"service_account": "foo"}`, false},
		{"trailing spaces", `{"service_account": "foo"}  `, `{"service_account": "foo"}`, false},
		{"leading+trailing spaces", `   {"service_account": "foo"}  `, `{"service_account": "foo"}`, false},
		{"base64", "eyJzZXJ2aWNlX2FjY291bnQiOiAiZm9vIn0=", `{"service_account": "foo"}`, false},
		{"invalid base64", "--eyJzZXJ2aWNlX2FjY291bnQiOiAiZm9vIn0=--", "", true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			gotServiceAccount, err := normalizeServiceAccount(tc.serviceAccount)
			assert.True(t, (err != nil) == tc.wantError)
			assert.Equal(t, tc.expectedServiceAccount, gotServiceAccount)
		})
	}
}
