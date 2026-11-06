package config_test

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/testenv"
	"github.com/pomerium/pomerium/internal/testenv/scenarios"
	"github.com/pomerium/pomerium/internal/testenv/snippets"
	"github.com/pomerium/pomerium/internal/testenv/upstreams"
	"github.com/pomerium/pomerium/pkg/nullable"
)

func TestOutboundProxy(t *testing.T) {
	env := testenv.New(t)

	dial := testenv.OverrideDialContext((&net.Dialer{}).DialContext)
	proxyA := newConnectProxy(t, dial)
	proxyB := newConnectProxy(t, dial)
	env.Add(testenv.ModifierFunc(func(_ context.Context, cfg *config.Config) {
		cfg.Options.OutboundHttpsProxy = nullable.From(proxyA.URL)
	}))
	env.Add(scenarios.NewIDP([]*scenarios.User{{Email: "test@example.com"}}))

	up := upstreams.HTTP(nil)
	up.Handle("/", func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte("OK"))
	})
	route := up.Route().
		From(env.SubdomainURL("http")).
		Policy(func(p *config.Policy) { p.AllowAnyAuthenticatedUser = true })
	env.AddUpstream(up)

	env.Start()
	snippets.WaitStartupComplete(env)

	// The browser connects directly, so only Pomerium's requests reach a proxy.
	browserTransport := http.DefaultTransport.(*http.Transport).Clone()
	browserTransport.Proxy = nil
	browserTransport.TLSClientConfig = &tls.Config{RootCAs: env.ServerCAs()}

	// signIn signs in with a new cookie jar, so each call goes through the
	// identity provider login flow.
	signIn := func() {
		jar, err := cookiejar.New(nil)
		require.NoError(t, err)
		browser := &http.Client{Transport: browserTransport, Jar: jar}

		res, err := up.Get(route,
			upstreams.AuthenticateAs("test@example.com"),
			upstreams.ClientHook(func(*http.Client) *http.Client { return browser }))
		require.NoError(t, err)
		defer res.Body.Close()
		body, err := io.ReadAll(res.Body)
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, res.StatusCode, string(body))
	}

	signIn()
	assert.NotZero(t, proxyA.Connects("mock-idp."), "identity provider requests go through outbound_https_proxy")

	env.Add(testenv.ModifierFunc(func(_ context.Context, cfg *config.Config) {
		cfg.Options.OutboundHttpsProxy = nullable.From(proxyB.URL)
	}))
	connectsA := proxyA.Connects("mock-idp.")

	signIn()
	assert.NotZero(t, proxyB.Connects("mock-idp."), "identity provider requests go through the updated outbound_https_proxy")
	assert.Equal(t, connectsA, proxyA.Connects("mock-idp."), "the previous outbound_https_proxy is no longer used")
}
