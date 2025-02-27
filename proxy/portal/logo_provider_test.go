package portal

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/pomerium/pomerium/internal/testutil"
)

func TestLogoProvider(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/icon":
			w.Header().Set("Content-Type", "image/vnd.microsoft.icon")
			io.WriteString(w, "NOT ACTUALLY AN ICON")
		case "/":
			io.WriteString(w, `<!doctype html><html><head><link rel="icon" href="/icon" /></head><body></body></html>`)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)

	ctx := testutil.GetContext(t, time.Minute)
	p := NewLogoProvider()
	u, err := p.GetLogoURL(ctx, "", srv.URL)
	assert.NoError(t, err)
	assert.Equal(t, "data:image/vnd.microsoft.icon;base64,Tk9UIEFDVFVBTExZIEFOIElDT04=", u)
}

func TestLogoProvider_Timeout(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-time.After(time.Second):
		}
		http.NotFound(w, r)
	}))
	t.Cleanup(srv.Close)

	ctx := testutil.GetContext(t, time.Minute)
	p := newFaviconDiscoveryLogoProvider()
	p.discoveryTimeout = time.Millisecond
	_, err := p.GetLogoURL(ctx, "", srv.URL)
	assert.ErrorIs(t, err, context.DeadlineExceeded)
}
