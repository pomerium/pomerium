package mcp

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"time"

	"golang.org/x/net/http/httpproxy"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/pkg/cryptutil"
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
//
// HTTP(S) proxies are honored from the environment (HTTPS_PROXY / NO_PROXY),
// read once when the client is constructed. (HTTP_PROXY never applies: every
// request is forced to https, and that variable governs http:// targets only.)
// Direct connections — where no proxy applies — still flow through
// DialTLSContext and get full internal-IP validation. When a proxy IS
// configured, Go tunnels via CONNECT and the proxy performs DNS resolution, so
// dial-time IP validation no longer applies on that path; egress filtering is
// then delegated to the operator-controlled proxy. HTTPS-only enforcement and
// the redirect ban still hold regardless of the proxy, and the upstream domain
// allowlist is checked (by hostname) at the application layer before any
// request is made.
//
// rootCAs, when non-nil, is used to verify server certificates on both the
// direct and proxied paths (e.g. for upstream servers using a private CA from
// the Pomerium configuration). A nil pool uses the system roots.
func NewSSRFSafeClient(cfg *config.Config) (*http.Client, error) {
	// skip for testing environments
	// where test servers run on localhost.
	if cfg.Options.InsecureSkipMCPMetadataSSRFCheck {
		return http.DefaultClient, nil
	}

	var rootCAs *x509.CertPool
	if cfg.Options.CA != "" || cfg.Options.CAFile != "" {
		pool, caErr := cryptutil.GetCertPool(cfg.Options.CA, cfg.Options.CAFile)
		if caErr != nil {
			return nil, fmt.Errorf("failed to load CA certificates: %w", caErr)
		}
		rootCAs = pool
	}

	dialer := &net.Dialer{
		Timeout:   10 * time.Second,
		KeepAlive: 30 * time.Second,
	}

	proxyFunc := httpproxy.FromEnvironment().ProxyFunc()

	baseTLS := &tls.Config{
		MinVersion: tls.VersionTLS12,
		RootCAs:    rootCAs,
	}

	transport := &http.Transport{
		Proxy: func(req *http.Request) (*url.URL, error) {
			if req.URL.Scheme != "https" {
				return nil, fmt.Errorf("%w: only https is allowed", ErrSSRFBlocked)
			}
			return proxyFunc(req.URL)
		},
		DialContext:           dialer.DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          10,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		TLSClientConfig:       baseTLS.Clone(),
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

			cfg := baseTLS.Clone()
			cfg.ServerName = host

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
	}, nil
}
