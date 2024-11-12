package selftests_test

import (
	"net"
	"net/http"
	"net/http/httptrace"
	"testing"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/testenv"
	"github.com/pomerium/pomerium/internal/testenv/snippets"
	"github.com/pomerium/pomerium/internal/testenv/upstreams"
	"github.com/stretchr/testify/require"
)

func TestDNSOverrides(t *testing.T) {
	env := testenv.New(t)
	h := upstreams.HTTP(nil)
	h.Handle("/", func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte("OK"))
	})
	route := h.Route().From(env.SubdomainURL("foo")).Policy(func(p *config.Policy) {
		p.AllowPublicUnauthenticatedAccess = true
	})
	env.AddUpstream(h)

	env.Start()
	snippets.WaitStartupComplete(env)

	var traceHostPort, traceRemoteAddr string
	var dnsStartCalled, dnsEndCalled bool
	trace := httptrace.ClientTrace{
		DNSStart: func(_ httptrace.DNSStartInfo) {
			dnsStartCalled = true
		},
		DNSDone: func(_ httptrace.DNSDoneInfo) {
			dnsEndCalled = true
		},
		GetConn: func(hostPort string) {
			traceHostPort = hostPort
		},
		GotConn: func(gci httptrace.GotConnInfo) {
			traceRemoteAddr = gci.Conn.RemoteAddr().String()
		},
	}
	resp, err := h.Get(route, upstreams.WithClientTrace(&trace))
	require.NoError(t, err)
	require.False(t, dnsStartCalled)
	require.False(t, dnsEndCalled)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	require.Equal(t, route.URL().Value(), "https://"+traceHostPort)
	host, _, err := net.SplitHostPort(traceRemoteAddr)
	require.NoError(t, err)
	require.True(t, net.ParseIP(host).IsLoopback())
}
