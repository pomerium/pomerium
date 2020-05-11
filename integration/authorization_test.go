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
				flows.WithEmail("bob@dogs.test"), flows.WithGroups("user"))
			if assert.NoError(t, err) {
				assert.Equal(t, http.StatusOK, res.StatusCode, "expected OK for dogs.test")
			}
		})
		t.Run("not allowed", func(t *testing.T) {
			client := testcluster.NewHTTPClient()
			res, err := flows.Authenticate(ctx, client, mustParseURL("https://httpdetails.localhost.pomerium.io/by-domain"),
				flows.WithEmail("joe@cats.test"), flows.WithGroups("user"))
			if assert.NoError(t, err) {
				assertDeniedAccess(t, res, "expected Forbidden for cats.test")
			}
		})
	})
	t.Run("users", func(t *testing.T) {
		t.Run("allowed", func(t *testing.T) {
			client := testcluster.NewHTTPClient()
			res, err := flows.Authenticate(ctx, client, mustParseURL("https://httpdetails.localhost.pomerium.io/by-user"),
				flows.WithEmail("bob@dogs.test"), flows.WithGroups("user"))
			if assert.NoError(t, err) {
				assert.Equal(t, http.StatusOK, res.StatusCode, "expected OK for bob@dogs.test")
			}
		})
		t.Run("not allowed", func(t *testing.T) {
			client := testcluster.NewHTTPClient()
			res, err := flows.Authenticate(ctx, client, mustParseURL("https://httpdetails.localhost.pomerium.io/by-user"),
				flows.WithEmail("joe@cats.test"), flows.WithGroups("user"))
			if assert.NoError(t, err) {
				assertDeniedAccess(t, res, "expected Forbidden for joe@cats.test")
			}
		})
	})
	t.Run("groups", func(t *testing.T) {
		t.Run("allowed", func(t *testing.T) {
			client := testcluster.NewHTTPClient()
			res, err := flows.Authenticate(ctx, client, mustParseURL("https://httpdetails.localhost.pomerium.io/by-group"),
				flows.WithEmail("bob@dogs.test"), flows.WithGroups("admin", "user"))
			if assert.NoError(t, err) {
				assert.Equal(t, http.StatusOK, res.StatusCode, "expected OK for admin")
			}
		})
		t.Run("not allowed", func(t *testing.T) {
			client := testcluster.NewHTTPClient()
			res, err := flows.Authenticate(ctx, client, mustParseURL("https://httpdetails.localhost.pomerium.io/by-group"),
				flows.WithEmail("joe@cats.test"), flows.WithGroups("user"))
			if assert.NoError(t, err) {
				assertDeniedAccess(t, res, "expected Forbidden for user, but got %d", res.StatusCode)
			}
		})
	})

	t.Run("refresh", func(t *testing.T) {
		client := testcluster.NewHTTPClient()
		res, err := flows.Authenticate(ctx, client, mustParseURL("https://httpdetails.localhost.pomerium.io/by-domain"),
			flows.WithEmail("bob@dogs.test"), flows.WithGroups("user"), flows.WithTokenExpiration(time.Second))
		if !assert.NoError(t, err) {
			return
		}
		assert.Equal(t, http.StatusOK, res.StatusCode, "expected OK for dogs.test")
		res.Body.Close()

		// poll till we get a new cookie because of a refreshed session
		ticker := time.NewTicker(time.Millisecond * 500)
		defer ticker.Stop()
		deadline := time.NewTimer(time.Second * 10)
		defer deadline.Stop()
		for i := 0; ; i++ {
			select {
			case <-ticker.C:
			case <-deadline.C:
				t.Fatal("timed out waiting for refreshed session")
				return
			case <-ctx.Done():
				t.Fatal("timed out waiting for refreshed session")
				return
			}

			res, err = client.Get(mustParseURL("https://httpdetails.localhost.pomerium.io/by-domain").String())
			if !assert.NoError(t, err) {
				return
			}
			res.Body.Close()
			if !assert.Equal(t, http.StatusOK, res.StatusCode, "failed after %d times", i+1) {
				return
			}
			if res.Header.Get("Set-Cookie") != "" {
				break
			}
		}
	})
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
