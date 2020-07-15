package authorize

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestGCPIdentityTokenSource(t *testing.T) {
	originalGCPIdentityDocURL := gcpIdentityDocURL
	defer func() {
		gcpIdentityDocURL = originalGCPIdentityDocURL
		gcpIdentityNow = time.Now
	}()

	now := time.Date(2020, 1, 1, 1, 0, 0, 0, time.Local)
	gcpIdentityNow = func() time.Time {
		return now
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "Google", r.Header.Get("Metadata-Flavor"))
		assert.Equal(t, "full", r.URL.Query().Get("format"))
		assert.Equal(t, "example", r.URL.Query().Get("audience"))
		_, _ = w.Write([]byte(now.Format(time.RFC3339)))
	}))
	defer srv.Close()

	gcpIdentityDocURL = srv.URL

	token, err := gcpIdentityTokenSource.Get(context.Background(), "example")
	assert.NoError(t, err)
	assert.Equal(t, "2020-01-01T01:00:00-07:00", token)

	now = time.Date(2020, 1, 1, 1, 49, 0, 0, time.Local)
	token, err = gcpIdentityTokenSource.Get(context.Background(), "example")
	assert.NoError(t, err)
	assert.Equal(t, "2020-01-01T01:00:00-07:00", token)

	now = time.Date(2020, 1, 1, 1, 51, 0, 0, time.Local)
	token, err = gcpIdentityTokenSource.Get(context.Background(), "example")
	assert.NoError(t, err)
	assert.Equal(t, "2020-01-01T01:51:00-07:00", token)
}
