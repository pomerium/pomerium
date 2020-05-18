package main

import (
	"context"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestDashboard(t *testing.T) {
	ctx := mainCtx
	ctx, clearTimeout := context.WithTimeout(ctx, time.Second*30)
	defer clearTimeout()

	t.Run("image asset", func(t *testing.T) {
		client := testcluster.NewHTTPClient()

		req, err := http.NewRequestWithContext(ctx, "GET", "https://httpdetails.localhost.pomerium.io/.pomerium/assets/img/pomerium.svg", nil)
		if err != nil {
			t.Fatal(err)
		}

		res, err := client.Do(req)
		if !assert.NoError(t, err, "unexpected http error") {
			return
		}
		defer res.Body.Close()

		assert.Equal(t, http.StatusOK, res.StatusCode, "unexpected status code")
		assert.Equal(t, "image/svg+xml", res.Header.Get("Content-Type"))
	})
	t.Run("forward auth image asset", func(t *testing.T) {
		client := testcluster.NewHTTPClient()

		req, err := http.NewRequestWithContext(ctx, "GET", "https://fa-httpdetails.localhost.pomerium.io/.pomerium/assets/img/pomerium.svg", nil)
		if err != nil {
			t.Fatal(err)
		}

		res, err := client.Do(req)
		if !assert.NoError(t, err, "unexpected http error") {
			return
		}
		defer res.Body.Close()

		assert.Equal(t, http.StatusOK, res.StatusCode, "unexpected status code")
		assert.Equal(t, "image/svg+xml", res.Header.Get("Content-Type"))
	})
}

func TestHealth(t *testing.T) {
	ctx := mainCtx
	ctx, clearTimeout := context.WithTimeout(ctx, time.Second*30)
	defer clearTimeout()
	pomeriumRoutes := []string{
		"authenticate.localhost.pomerium.io",
		"authorize.default.svc.cluster.local:5080",
		"cache.default.svc.cluster.local:5080",
		"forward-authenticate.localhost.pomerium.io",
		"restricted-httpdetails.localhost.pomerium.io",
		"httpdetails.localhost.pomerium.io",
	}
	endpoints := []string{"healthz", "ping"}

	for _, route := range pomeriumRoutes {
		for _, endpoint := range endpoints {
			endpoint := endpoint
			t.Run(endpoint, func(t *testing.T) {
				client := testcluster.NewHTTPClient()
				routeToCheck := fmt.Sprintf("https://%s/%s", route, endpoint)
				req, err := http.NewRequestWithContext(ctx, "GET", routeToCheck, nil)
				if err != nil {
					t.Fatal(err)
				}

				res, err := client.Do(req)
				if !assert.NoError(t, err, "unexpected http error") {
					return
				}
				defer res.Body.Close()

				assert.Equal(t, http.StatusOK, res.StatusCode, "unexpected status code")
			})
		}
	}

}
