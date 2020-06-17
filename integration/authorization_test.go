package main

import (
	"context"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/pomerium/pomerium/integration/internal/flows"
)

func TestAuthorization(t *testing.T) {
	ctx, clearTimeout := context.WithTimeout(mainCtx, time.Second*30)
	defer clearTimeout()

	accessType := []string{"direct", "api"}
	for _, at := range accessType {
		t.Run(at, func(t *testing.T) {
			var withAPI flows.AuthenticateOption

			if at == "api" {
				withAPI = flows.WithAPI()
			}

			t.Run("public", func(t *testing.T) {
				client := testcluster.NewHTTPClient()

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
					client := testcluster.NewHTTPClient()
					res, err := flows.Authenticate(ctx, client, mustParseURL("https://httpdetails.localhost.pomerium.io/by-domain"),
						withAPI, flows.WithEmail("bob@dogs.test"), flows.WithGroups("user"))
					if assert.NoError(t, err) {
						assert.Equal(t, http.StatusOK, res.StatusCode, "expected OK for dogs.test")
					}
				})
				t.Run("not allowed", func(t *testing.T) {
					client := testcluster.NewHTTPClient()
					res, err := flows.Authenticate(ctx, client, mustParseURL("https://httpdetails.localhost.pomerium.io/by-domain"),
						withAPI, flows.WithEmail("joe@cats.test"), flows.WithGroups("user"))
					if assert.NoError(t, err) {
						assertDeniedAccess(t, res, "expected Forbidden for cats.test")
					}
				})
			})
			t.Run("users", func(t *testing.T) {
				t.Run("allowed", func(t *testing.T) {
					client := testcluster.NewHTTPClient()
					res, err := flows.Authenticate(ctx, client, mustParseURL("https://httpdetails.localhost.pomerium.io/by-user"),
						withAPI, flows.WithEmail("bob@dogs.test"), flows.WithGroups("user"))
					if assert.NoError(t, err) {
						assert.Equal(t, http.StatusOK, res.StatusCode, "expected OK for bob@dogs.test")
					}
				})
				t.Run("not allowed", func(t *testing.T) {
					client := testcluster.NewHTTPClient()
					res, err := flows.Authenticate(ctx, client, mustParseURL("https://httpdetails.localhost.pomerium.io/by-user"),
						withAPI, flows.WithEmail("joe@cats.test"), flows.WithGroups("user"))
					if assert.NoError(t, err) {
						assertDeniedAccess(t, res, "expected Forbidden for joe@cats.test")
					}
				})
			})
		})
	}
}

func mustParseURL(str string) *url.URL {
	u, err := url.Parse(str)
	if err != nil {
		panic(err)
	}
	return u
}

func assertDeniedAccess(t *testing.T, res *http.Response, msgAndArgs ...interface{}) bool {
	return assert.Condition(t, func() bool {
		return res.StatusCode == http.StatusForbidden || res.StatusCode == http.StatusUnauthorized
	}, msgAndArgs...)
}
