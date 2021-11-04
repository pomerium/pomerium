package authclient

import (
	"context"
	"net"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/go-chi/chi"
	"github.com/stretchr/testify/assert"
)

func TestAuthClient(t *testing.T) {
	ctx, clearTimeout := context.WithTimeout(context.Background(), time.Second*30)
	defer clearTimeout()

	li, err := net.Listen("tcp", "127.0.0.1:0")
	if !assert.NoError(t, err) {
		return
	}
	defer func() { _ = li.Close() }()

	go func() {
		h := chi.NewMux()
		h.Get("/.pomerium/api/v1/login", func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte(r.FormValue("pomerium_redirect_uri")))
		})
		srv := &http.Server{
			BaseContext: func(li net.Listener) context.Context {
				return ctx
			},
			Handler: h,
		}
		_ = srv.Serve(li)
	}()

	ac := New()
	ac.cfg.open = func(input string) error {
		u, err := url.Parse(input)
		if err != nil {
			return err
		}
		u = u.ResolveReference(&url.URL{
			RawQuery: url.Values{
				"pomerium_jwt": {"TEST"},
			}.Encode(),
		})

		req, err := http.NewRequestWithContext(ctx, "GET", u.String(), nil)
		if err != nil {
			return err
		}

		res, err := http.DefaultClient.Do(req)
		if err != nil {
			return err
		}
		_ = res.Body.Close()
		return nil
	}

	rawJWT, err := ac.GetJWT(ctx, &url.URL{
		Scheme: "http",
		Host:   li.Addr().String(),
	}, func(_ string) {})
	assert.NoError(t, err)
	assert.Equal(t, "TEST", rawJWT)
}
