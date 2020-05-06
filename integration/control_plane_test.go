package main

import (
	"context"
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

	for _, endpoint := range []string{"healthz", "ping"} {
		endpoint := endpoint
		t.Run(endpoint, func(t *testing.T) {
			client := testcluster.NewHTTPClient()

			req, err := http.NewRequestWithContext(ctx, "GET", "https://restricted-httpdetails.localhost.pomerium.io/"+endpoint, nil)
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
