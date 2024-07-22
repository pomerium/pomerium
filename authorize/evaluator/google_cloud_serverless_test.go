package evaluator_test

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/pomerium/pomerium/authorize/evaluator"
)

func withMockGCP(t *testing.T, f func()) {
	originalGCPIdentityDocURL := evaluator.GCPIdentityDocURL
	defer func() {
		evaluator.GCPIdentityDocURL = originalGCPIdentityDocURL
		evaluator.GCPIdentityNow = time.Now
	}()

	now := time.Date(2020, 1, 1, 1, 0, 0, 0, time.UTC)
	evaluator.GCPIdentityNow = func() time.Time {
		return now
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "Google", r.Header.Get("Metadata-Flavor"))
		assert.Equal(t, "full", r.URL.Query().Get("format"))
		_, _ = w.Write([]byte(now.Format(time.RFC3339)))
	}))
	defer srv.Close()

	evaluator.GCPIdentityDocURL = srv.URL
	f()
}

func TestGCPIdentityTokenSource(t *testing.T) {
	withMockGCP(t, func() {
		src, err := evaluator.XGetGoogleCloudServerlessTokenSource("", "example")
		assert.NoError(t, err)

		token, err := src.Token()
		assert.NoError(t, err)
		assert.Equal(t, "2020-01-01T01:00:00Z", token.AccessToken)
	})
}

func Test_normalizeServiceAccount(t *testing.T) {
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
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			gotServiceAccount, err := evaluator.XNormalizeServiceAccount(tc.serviceAccount)
			assert.True(t, (err != nil) == tc.wantError)
			assert.Equal(t, tc.expectedServiceAccount, gotServiceAccount)
		})
	}
}
