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

	accessType := []string{"direct", "api"}
	for _, at := range accessType {
		t.Run(at, func(t *testing.T) {
			var withAPI, withForwardAuth flows.AuthenticateOption

			if at == "api" {
				if ClusterType == "traefik" || ClusterType == "nginx" {
					t.Skip()
					return
				}
				withAPI = flows.WithAPI()
			}

			if ClusterType == "nginx" {
				withForwardAuth = flows.WithForwardAuth(true)
			}

			t.Run("public", func(t *testing.T) {
				client := getClient()

				req, err := http.NewRequestWithContext(ctx, "GET", "https://httpdetails.localhost.pomerium.io", nil)
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
					client := getClient()
					res, err := flows.Authenticate(ctx, client, mustParseURL("https://httpdetails.localhost.pomerium.io/by-domain"),
						withAPI, withForwardAuth, flows.WithEmail("user1@dogs.test"))
					if assert.NoError(t, err) {
						assert.Equal(t, http.StatusOK, res.StatusCode, "expected OK for dogs.test")
					}
				})
				t.Run("not allowed", func(t *testing.T) {
					client := getClient()
					res, err := flows.Authenticate(ctx, client, mustParseURL("https://httpdetails.localhost.pomerium.io/by-domain"),
						withAPI, withForwardAuth, flows.WithEmail("user1@cats.test"))
					if assert.NoError(t, err) {
						assertDeniedAccess(t, res, "expected Forbidden for cats.test, but got: %d", res.StatusCode)
					}
				})
			})
		})
	}
}

func assertDeniedAccess(t *testing.T, res *http.Response, msgAndArgs ...interface{}) bool {
	return assert.Condition(t, func() bool {
		return res.StatusCode == http.StatusForbidden || res.StatusCode == http.StatusUnauthorized
	}, msgAndArgs...)
}
