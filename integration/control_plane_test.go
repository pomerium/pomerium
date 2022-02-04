package main

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestDashboard(t *testing.T) {
	ctx, clearTimeout := context.WithTimeout(context.Background(), time.Second*30)
	defer clearTimeout()

	t.Run("user dashboard", func(t *testing.T) {
		req, err := http.NewRequestWithContext(ctx, "GET", "https://authenticate.localhost.pomerium.io/.pomerium/", nil)
		if err != nil {
			t.Fatal(err)
		}

		res, err := getClient().Do(req)
		if !assert.NoError(t, err, "unexpected http error") {
			return
		}
		defer res.Body.Close()

		body, _ := io.ReadAll(res.Body)

		assert.Equal(t, http.StatusFound, res.StatusCode, "unexpected status code: %s", body)
	})
	t.Run("dashboard strict slash redirect", func(t *testing.T) {
		req, err := http.NewRequestWithContext(ctx, "GET", "https://authenticate.localhost.pomerium.io/.pomerium", nil)
		if err != nil {
			t.Fatal(err)
		}

		res, err := getClient().Do(req)
		if !assert.NoError(t, err, "unexpected http error") {
			return
		}
		defer res.Body.Close()

		assert.Equal(t, 3, res.StatusCode/100, "unexpected status code")
	})
}

func TestHealth(t *testing.T) {
	if ClusterType == "traefik" || ClusterType == "nginx" {
		t.Skip()
		return
	}

	ctx, clearTimeout := context.WithTimeout(context.Background(), time.Second*30)
	defer clearTimeout()

	pomeriumRoutes := []string{
		"https://authenticate.localhost.pomerium.io",
		"https://httpdetails.localhost.pomerium.io",
		"https://restricted-httpdetails.localhost.pomerium.io",
	}
	endpoints := []string{"healthz", "ping"}

	for _, route := range pomeriumRoutes {
		route := route
		for _, endpoint := range endpoints {
			endpoint := endpoint
			routeToCheck := fmt.Sprintf("%s/%s", route, endpoint)
			t.Run(routeToCheck, func(t *testing.T) {
				req, err := http.NewRequestWithContext(ctx, "GET", routeToCheck, nil)
				if err != nil {
					t.Fatal(err)
				}

				res, err := getClient().Do(req)
				if !assert.NoError(t, err, "unexpected http error") {
					return
				}
				defer res.Body.Close()

				assert.Equal(t, http.StatusOK, res.StatusCode, "unexpected status code")
			})
		}
	}
}
