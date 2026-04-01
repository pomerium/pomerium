package mcp

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"time"
)

// ErrSSRFBlocked is returned when a request is blocked by SSRF protection.
var ErrSSRFBlocked = errors.New("ssrf protection")

// isInternalOrSpecial returns true if the IP address is private, loopback, link-local,
// multicast, or otherwise not a public unicast address.
func isInternalOrSpecial(ip netip.Addr) bool {
	ip = ip.Unmap()
	return !ip.IsValid() ||
		ip.IsPrivate() ||
		ip.IsLoopback() ||
		ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() ||
		ip.IsMulticast() ||
		ip.IsUnspecified()
}

// resolveAndValidate resolves a hostname to IP addresses and returns the first
// non-internal address. Returns an error if all resolved IPs are internal/special
// or if the hostname is an IP literal pointing to an internal address.
func resolveAndValidate(ctx context.Context, host string) (netip.Addr, error) {
	// If host is an IP literal, check it directly.
	if ip, err := netip.ParseAddr(host); err == nil {
		if isInternalOrSpecial(ip) {
			return netip.Addr{}, fmt.Errorf("%w: blocked IP literal %s", ErrSSRFBlocked, ip)
		}
		return ip, nil
	}

	addrs, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return netip.Addr{}, err
	}

	for _, a := range addrs {
		ip, ok := netip.AddrFromSlice(a.IP)
		if !ok {
			continue
		}
		if !isInternalOrSpecial(ip) {
			return ip, nil
		}
	}
	return netip.Addr{}, fmt.Errorf("%w: all resolved IPs for %q are internal", ErrSSRFBlocked, host)
}

// httpsOnlyTransport wraps an http.RoundTripper to enforce HTTPS-only requests.
type httpsOnlyTransport struct {
	base http.RoundTripper
}

func (t *httpsOnlyTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.URL == nil || req.URL.Scheme != "https" {
		return nil, fmt.Errorf("%w: only https is allowed", ErrSSRFBlocked)
	}
	return t.base.RoundTrip(req)
}

// NewSSRFSafeClient creates an *http.Client that enforces HTTPS-only requests,
// blocks connections to private/loopback/internal IP addresses, and refuses
// to follow HTTP redirects.
//
// Redirects are blocked because the OAuth metadata specs (RFC 8414 §3.2,
// RFC 9728 §3.2) require a successful response to use 200 OK. Following
// redirects would also undermine SSRF protection by allowing an attacker-
// controlled endpoint to bounce requests to internal services.
func NewSSRFSafeClient() *http.Client {
	dialer := &net.Dialer{
		Timeout:   10 * time.Second,
		KeepAlive: 30 * time.Second,
	}

	transport := &http.Transport{
		Proxy:                 nil, // disable proxy to prevent bypass
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          10,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			host, port, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, err
			}

			ip, err := resolveAndValidate(ctx, host)
			if err != nil {
				return nil, err
			}

			rawConn, err := dialer.DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
			if err != nil {
				return nil, err
			}

			cfg := &tls.Config{
				MinVersion: tls.VersionTLS12,
				ServerName: host,
			}

			tlsConn := tls.Client(rawConn, cfg)
			if err := tlsConn.HandshakeContext(ctx); err != nil {
				rawConn.Close()
				return nil, err
			}
			return tlsConn, nil
		},
	}

	return &http.Client{
		Transport: &httpsOnlyTransport{base: transport},
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			// OAuth metadata specs (RFC 8414 §3.2, RFC 9728 §3.2) require 200 OK
			// for successful responses. Redirects should not be followed for
			// metadata fetches; they also represent an SSRF amplification vector.
			return fmt.Errorf("%w: redirects are not allowed", ErrSSRFBlocked)
		},
		Timeout: 30 * time.Second,
	}
}
