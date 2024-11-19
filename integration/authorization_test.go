package main

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/pomerium/pomerium/integration/flows"
)

func TestAuthorization(t *testing.T) {
	ctx, clearTimeout := context.WithTimeout(context.Background(), time.Second*30)
	defer clearTimeout()

	withBrowserAcceptHeader := flows.WithRequestHeader("Accept",
		"text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7")

	accessType := []string{"direct", "api"}
	for _, at := range accessType {
		t.Run(at, func(t *testing.T) {
			var withAPI flows.AuthenticateOption

			if at == "api" {
				withAPI = flows.WithAPI()
			}

			t.Run("public", func(t *testing.T) {
				client := getClient(t, false)

				req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://httpdetails.localhost.pomerium.io", nil)
				if err != nil {
					t.Fatal(err)
				}

				res, err := client.Do(req)
				if !assert.NoError(t, err, "unexpected http error") {
					return
				}
				defer res.Body.Close()

				assert.Equal(t, http.StatusOK, res.StatusCode, "unexpected status code, headers=%v", res.Header)
			})

			t.Run("domains", func(t *testing.T) {
				t.Run("allowed", func(t *testing.T) {
					client := getClient(t, false)
					res, err := flows.Authenticate(ctx, client, mustParseURL("https://httpdetails.localhost.pomerium.io/by-domain"),
						withAPI, flows.WithEmail("user1@dogs.test"), withBrowserAcceptHeader)
					if assert.NoError(t, err) {
						assert.Equal(t, http.StatusOK, res.StatusCode, "expected OK for dogs.test")
					}
				})
				t.Run("not allowed", func(t *testing.T) {
					client := getClient(t, false)
					res, err := flows.Authenticate(ctx, client, mustParseURL("https://httpdetails.localhost.pomerium.io/by-domain"),
						withAPI, flows.WithEmail("user1@cats.test"), withBrowserAcceptHeader)
					if assert.NoError(t, err) {
						assertDeniedAccess(t, res, "expected Forbidden for cats.test, but got: %d", res.StatusCode)
						assert.Contains(t, res.Header.Get("Content-Type"), "text/html")
					}
				})
			})
		})
	}
}

func assertDeniedAccess(t *testing.T, res *http.Response, msgAndArgs ...any) bool {
	return assert.Condition(t, func() bool {
		return res.StatusCode == http.StatusForbidden || res.StatusCode == http.StatusUnauthorized
	}, msgAndArgs...)
}
