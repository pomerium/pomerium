package httputil

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"

	"github.com/pires/go-proxyproto"
)

// NewTransport makes sure we inherit the default transport settings from http.DefaultTransport.
//
// Unset fields accidentally caused a socket/memory leak with go 1.27's changes to
// idle connections.
//
//	https://github.com/pomerium/pomerium/issues/7027
func NewTransport(modify func(*http.Transport)) *http.Transport {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	modify(transport)
	return transport
}

// GetInsecureTransport gets an insecure HTTP transport.
func GetInsecureTransport() *http.Transport {
	return NewTransport(func(transport *http.Transport) {
		SetTLSClientConfig(transport, &tls.Config{InsecureSkipVerify: true})
	})
}

// SetTLSClientConfig sets cfg and clears any inherited DialTLS or
// DialTLSContext, either of which would bypass it.
func SetTLSClientConfig(transport *http.Transport, cfg *tls.Config) {
	clearTLSDialers(transport)
	transport.TLSClientConfig = cfg
}

// NewLocalProxyProtocolTransport creates a new http transport that uses the proxy
// protocol with the LOCAL command. The base protocol is cloned and a new transport
// is returned. The base's DialTLS and DialTLSContext are cleared, because a TLS
// dialer opens its own connection and would never send the header.
func NewLocalProxyProtocolTransport(base *http.Transport) *http.Transport {
	transport := base.Clone()
	clearTLSDialers(transport)
	originalDial := transport.Dial
	originalDialContext := transport.DialContext
	baseDial := func(ctx context.Context, network, addr string) (net.Conn, error) {
		if originalDialContext != nil {
			return originalDialContext(ctx, network, addr)
		}
		if originalDial != nil {
			return originalDial(network, addr)
		}
		var zeroDialer net.Dialer
		return zeroDialer.DialContext(ctx, network, addr)
	}
	transport.Dial = nil
	transport.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		conn, err := baseDial(ctx, network, addr)
		if err == nil {
			header := &proxyproto.Header{
				Version: 2,
				Command: proxyproto.LOCAL,
			}
			_, err = header.WriteTo(conn)
			if err != nil {
				_ = conn.Close()
				return nil, err
			}
		}
		return conn, err
	}
	return transport
}

func clearTLSDialers(transport *http.Transport) {
	transport.DialTLS = nil
	transport.DialTLSContext = nil
}
