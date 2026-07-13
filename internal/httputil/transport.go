package httputil

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"

	"github.com/pires/go-proxyproto"
)

// GetInsecureTransport gets an insecure HTTP transport.
func GetInsecureTransport() *http.Transport {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.DialTLS = nil
	transport.DialTLSContext = nil
	transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	return transport
}

// NewLocalProxyProtocolTransport creates a new http transport that uses the proxy
// protocol with the LOCAL command. The base protocol is cloned and a new transport
// is returned.
func NewLocalProxyProtocolTransport(base *http.Transport) *http.Transport {
	if base == nil {
		base = http.DefaultTransport.(*http.Transport)
	}
	transport := base.Clone()
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
