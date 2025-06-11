package reproxy

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

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

		cfg := &config.Config{
			Options: &config.Options{
				SharedKey: cryptutil.NewBase64Key(),
				Policies: []config.Policy{{
					To:                            config.WeightedURLs{{URL: *u}},
					KubernetesServiceAccountToken: "ABCD",
				}},
			},
		}
		h.Update(t.Context(), cfg)

		policyID, _ := cfg.Options.Policies[0].RouteID()

		req, err := http.NewRequest(http.MethodGet, srv2.URL, nil)
		require.NoError(t, err)
		for _, hdr := range h.GetPolicyIDHeaders(policyID) {
			req.Header.Set(hdr[0], hdr[1])
		}

		res, err := http.DefaultClient.Do(req)
		require.NoError(t, err)

		body, err := io.ReadAll(res.Body)
		require.NoError(t, err)
		res.Body.Close()

		assert.Equal(t, "SERVER1", string(body))
	})
}
