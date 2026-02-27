package authenticateflow_test

import (
	"fmt"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/testenv"
	"github.com/pomerium/pomerium/internal/testenv/scenarios"
	"github.com/pomerium/pomerium/internal/testenv/snippets"
	"github.com/pomerium/pomerium/internal/testenv/upstreams"
	"github.com/pomerium/pomerium/internal/testenv/values"
)

func TestPKCELogin(t *testing.T) {
	env := testenv.New(t)

	env.Add(scenarios.NewIDP(
		[]*scenarios.User{{Email: "test@example.com"}},
		scenarios.WithEnablePKCE(true),
	))

	up := upstreams.HTTP(nil)
	up.Handle("/", func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprintln(w, "ok")
	})
	route := up.Route().
		From(env.SubdomainURL("app")).
		To(values.Bind(up.Addr(), func(addr string) string {
			return fmt.Sprintf("http://%s", addr)
		})).
		Policy(func(p *config.Policy) { p.AllowAnyAuthenticatedUser = true })
	env.AddUpstream(up)
	env.Start()
	snippets.WaitStartupComplete(env)

	resp, err := up.Get(route, upstreams.AuthenticateAs("test@example.com"))
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

func TestPKCEMultiTab(t *testing.T) {
	env := testenv.New(t)

	env.Add(scenarios.NewIDP(
		[]*scenarios.User{{Email: "user1@example.com"}, {Email: "user2@example.com"}},
		scenarios.WithEnablePKCE(true),
	))

	upA := upstreams.HTTP(nil)
	upA.Handle("/", func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprintln(w, "upstream-a")
	})
	routeA := upA.Route().
		From(env.SubdomainURL("app-a")).
		To(values.Bind(upA.Addr(), func(addr string) string {
			return fmt.Sprintf("http://%s", addr)
		})).
		Policy(func(p *config.Policy) { p.AllowAnyAuthenticatedUser = true })
	env.AddUpstream(upA)

	upB := upstreams.HTTP(nil)
	upB.Handle("/", func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprintln(w, "upstream-b")
	})
	routeB := upB.Route().
		From(env.SubdomainURL("app-b")).
		To(values.Bind(upB.Addr(), func(addr string) string {
			return fmt.Sprintf("http://%s", addr)
		})).
		Policy(func(p *config.Policy) { p.AllowAnyAuthenticatedUser = true })
	env.AddUpstream(upB)

	env.Start()
	snippets.WaitStartupComplete(env)

	// Two separate clients (simulating two browser tabs) login with
	// distinct states. Both should succeed with PKCE per-state isolation.
	respA, err := upA.Get(routeA, upstreams.AuthenticateAs("user1@example.com"))
	require.NoError(t, err)
	respA.Body.Close()
	assert.Equal(t, http.StatusOK, respA.StatusCode)

	respB, err := upB.Get(routeB, upstreams.AuthenticateAs("user2@example.com"))
	require.NoError(t, err)
	respB.Body.Close()
	assert.Equal(t, http.StatusOK, respB.StatusCode)
}

func TestPKCEDisabledForNonAdvertisingIdP(t *testing.T) {
	env := testenv.New(t)

	// IDP without EnablePKCE — discovery won't advertise code_challenge_methods_supported.
	env.Add(scenarios.NewIDP(
		[]*scenarios.User{{Email: "test@example.com"}},
	))

	up := upstreams.HTTP(nil)
	up.Handle("/", func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprintln(w, "ok")
	})
	route := up.Route().
		From(env.SubdomainURL("app")).
		To(values.Bind(up.Addr(), func(addr string) string {
			return fmt.Sprintf("http://%s", addr)
		})).
		Policy(func(p *config.Policy) { p.AllowAnyAuthenticatedUser = true })
	env.AddUpstream(up)
	env.Start()
	snippets.WaitStartupComplete(env)

	// Login should still succeed without PKCE — graceful degradation.
	resp, err := up.Get(route, upstreams.AuthenticateAs("test@example.com"))
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)
}
