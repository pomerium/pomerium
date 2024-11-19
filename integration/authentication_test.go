package main

import (
	"context"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v3/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pomerium/pomerium/integration/flows"
	"github.com/pomerium/pomerium/pkg/slices"
)

func TestRouteSessions(t *testing.T) {
	ctx, clearTimeout := context.WithTimeout(context.Background(), time.Second*30)
	defer clearTimeout()

	testHTTPClient(t, func(t *testing.T, client *http.Client) {
		// Sign in to access one route.
		url1 := mustParseURL("https://httpdetails.localhost.pomerium.io/by-domain")
		res, err := flows.Authenticate(ctx, client, url1, flows.WithEmail("user1@dogs.test"))
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, res.StatusCode, "expected OK for httpdetails")

		// Now request a different route. This should not require signing in again,
		// but will redirect through the authenticate service if using the
		// stateless authentication flow.
		client.CheckRedirect = nil
		url2 := mustParseURL("https://restricted-httpdetails.localhost.pomerium.io/by-domain")
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, url2.String(), nil)
		res, err = client.Do(req)
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, res.StatusCode, "expected OK for restricted-httpdetails")

		// Now examine the session cookies saved for each route.
		claims1 := getSessionCookieJWTClaims(t, client, url1)
		claims2 := getSessionCookieJWTClaims(t, client, url2)

		if AuthenticateFlow == "stateless" {
			// Under the stateless authenticate flow, each route should have its
			// own session.
			assert.NotEqual(t, claims1.ID, claims2.ID)
		} else {
			// Under the stateful authenticate flow, the two routes should share
			// the same session.
			assert.Equal(t, claims1.ID, claims2.ID)

			// The only cookies set on the authenticate service domain should be
			// "_pomerium_authenticate" and "_pomerium_csrf". (No identity profile
			// cookies should be present.)
			c := client.Jar.Cookies(mustParseURL("https://authenticate.localhost.pomerium.io"))
			assert.Equal(t, 2, len(c))
			cookieNames := slices.Map(c, func(c *http.Cookie) string { return c.Name })
			assert.ElementsMatch(t, []string{"_pomerium_authenticate", "_pomerium_csrf"}, cookieNames)
		}
	})
}

func getSessionCookieJWTClaims(t *testing.T, client *http.Client, u *url.URL) *jwt.Claims {
	t.Helper()
	cookie := getSessionCookie(t, client, u)

	token, err := jwt.ParseSigned(cookie.Value)
	require.NoError(t, err)

	var claims jwt.Claims
	err = token.UnsafeClaimsWithoutVerification(&claims)
	require.NoError(t, err)

	return &claims
}

func getSessionCookie(t *testing.T, client *http.Client, u *url.URL) *http.Cookie {
	t.Helper()
	for _, c := range client.Jar.Cookies(u) {
		if c.Name == "_pomerium" {
			return c
		}
	}
	t.Fatalf("no session cookie found for URL %q", u.String())
	return nil
}
