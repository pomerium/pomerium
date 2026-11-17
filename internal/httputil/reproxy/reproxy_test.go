package reproxy

import (
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/pkg/cryptutil"
)

func TestMiddleware(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		io.WriteString(w, "NEXT")
	})

	t.Run("next", func(t *testing.T) {
		h := New()

		srv := httptest.NewServer(h.Middleware(next))
		defer srv.Close()

		res, err := http.Get(srv.URL)
		require.NoError(t, err)

		body, err := io.ReadAll(res.Body)
		require.NoError(t, err)
		res.Body.Close()

		assert.Equal(t, "NEXT", string(body))
	})
	t.Run("proxy", func(t *testing.T) {
		h := New()

		srv1 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			io.WriteString(w, "SERVER1")
		}))
		defer srv1.Close()

		u, err := url.Parse(srv1.URL)
		require.NoError(t, err)

		srv2 := httptest.NewServer(h.Middleware(next))
		defer srv2.Close()

		cfg := config.New(&config.Options{
			SharedKey: cryptutil.NewBase64Key(),
			Policies: []config.Policy{{
				To:                            config.WeightedURLs{{URL: *u}},
				KubernetesServiceAccountToken: "ABCD",
			}},
		})
		h.Update(t.Context(), cfg)

		policyID, _ := cfg.Options.Policies[0].RouteID()

		assert.Equal(t, "SERVER1", getReproxied(t, h, srv2.URL, policyID))
	})
	t.Run("upstream connections", func(t *testing.T) {
		h := New()

		var opened, closed atomic.Int32
		upstream := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			io.WriteString(w, "UPSTREAM")
		}))
		upstream.Config.ConnState = func(_ net.Conn, state http.ConnState) {
			switch state {
			case http.StateNew:
				opened.Add(1)
			case http.StateClosed:
				closed.Add(1)
			}
		}
		upstream.Start()
		defer upstream.Close()

		u, err := url.Parse(upstream.URL)
		require.NoError(t, err)

		srv := httptest.NewServer(h.Middleware(next))
		defer srv.Close()

		cfg := config.New(&config.Options{
			SharedKey: cryptutil.NewBase64Key(),
			Policies: []config.Policy{{
				To:                            config.WeightedURLs{{URL: *u}},
				KubernetesServiceAccountToken: "ABCD",
			}},
		})
		h.Update(t.Context(), cfg)
		policyID, _ := cfg.Options.Policies[0].RouteID()

		for range 3 {
			assert.Equal(t, "UPSTREAM", getReproxied(t, h, srv.URL, policyID))
		}
		assert.Equal(t, int32(1), opened.Load(), "upstream connections opened")

		h.Update(t.Context(), config.New(&config.Options{}))
		assert.Eventually(t, func() bool {
			return opened.Load() == closed.Load()
		}, 5*time.Second, 10*time.Millisecond, "upstream connections closed after update")
	})
}

func getReproxied(t *testing.T, h *Handler, srvURL, policyID string) string {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, srvURL, nil)
	require.NoError(t, err)
	for _, hdr := range h.GetPolicyIDHeaders(policyID) {
		req.Header.Set(hdr[0], hdr[1])
	}
	res, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer res.Body.Close()
	body, err := io.ReadAll(res.Body)
	require.NoError(t, err)
	return string(body)
}
