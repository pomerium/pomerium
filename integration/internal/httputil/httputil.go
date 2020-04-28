package httputil

import (
	"context"
	"net"
	"net/http"
)

type localRoundTripper struct {
	underlying http.RoundTripper
	portToAddr map[string]string
}

func NewLocalRoundTripper(underlying http.RoundTripper, portToAddr map[string]string) http.RoundTripper {
	lrt := &localRoundTripper{underlying: underlying, portToAddr: portToAddr}
	return lrt
}

func (lrt *localRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	req = req.Clone(req.Context())
	req.URL.Host = lrt.remapHost(req.Context(), req.Host)
	return lrt.underlying.RoundTrip(req)
}

func (lrt *localRoundTripper) remapHost(ctx context.Context, hostport string) string {
	host, port, err := net.SplitHostPort(hostport)
	if err != nil {
		host = hostport
		port = "443"
	}

	dst, ok := lrt.portToAddr[port]
	if !ok {
		return hostport
	}

	ips, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil || len(ips) == 0 || ips[0].String() != "127.0.0.1" {
		return hostport
	}

	return dst

}
