package testenv

import (
	"context"
	"net"
	"net/http"
	"strings"
	"time"
)

const localDomainName = "localhost.pomerium.io"

type DialContextFunc = func(ctx context.Context, network string, addr string) (net.Conn, error)

var defaultDialer = &net.Dialer{
	Timeout:   30 * time.Second,
	KeepAlive: 30 * time.Second,
	Resolver: &net.Resolver{
		PreferGo: true,
	},
}

func init() {
	http.DefaultTransport.(*http.Transport).DialContext = OverrideDialContext(defaultDialer.DialContext)
}

func OverrideDialContext(defaultDialContext DialContextFunc) DialContextFunc {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, port, err := maybeSplitHostPort(addr)
		if err != nil {
			return nil, err
		}
		if strings.HasSuffix(host, localDomainName) {
			switch network {
			case "tcp", "tcp4", "udp", "udp4":
				host = "127.0.0.1"
			case "tcp6", "udp6":
				host = "::1"
			}
		}
		return defaultDialContext(ctx, network, net.JoinHostPort(host, port))
	}
}

func maybeSplitHostPort(s string) (string, string, error) {
	if strings.Contains(s, ":") {
		return net.SplitHostPort(s)
	}
	return s, "", nil
}

func GRPCContextDialer(ctx context.Context, target string) (net.Conn, error) {
	if strings.HasPrefix(target, "unix") {
		return defaultDialer.DialContext(ctx, "tcp", target)
	}
	host, port, err := net.SplitHostPort(target)
	if err != nil {
		return nil, err
	}
	if strings.HasSuffix(host, localDomainName) {
		return defaultDialer.DialContext(ctx, "tcp", "127.0.0.1:"+port)
	}
	return defaultDialer.DialContext(ctx, "tcp", target)
}
