package config

import (
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
)

// ValidateCookieSameSite validates the cookie same site option.
func ValidateCookieSameSite(value string) error {
	value = strings.ToLower(value)
	switch value {
	case "", "strict", "lax", "none":
		return nil
	}
	return fmt.Errorf("unknown cookie_same_site: %s", value)
}

// ValidateAgenticAddress validates the address the agentic authorization
// server's own listener binds to: an IPv4 loopback literal with a port.
//
// Loopback is a security requirement, not a preference. The AS's endpoints are
// authorized only by the routes that point at them — the handler itself verifies
// a workload JWT against every configured identity provider and runs no policy —
// so a listener reachable from anywhere else would answer with every one of
// those gates skipped.
//
// IPv4 specifically, because the listener is bound with reuseport.Listen("tcp4",
// ...): "[::1]:9300" is a perfectly good loopback address that then fails to
// bind, and a bind failure at that point is fatal. Rejecting it here turns a
// crash at startup into a config error that names the problem.
func ValidateAgenticAddress(addr string) error {
	ap, err := netip.ParseAddrPort(addr)
	if err != nil {
		return fmt.Errorf("expected an IPv4 loopback address literal and a port, e.g. 127.0.0.1:9300")
	}
	switch {
	case ap.Port() == 0:
		return fmt.Errorf("expected positive port number")
	case !ap.Addr().IsLoopback():
		return fmt.Errorf("must be a loopback address, got %q", ap.Addr())
	case !ap.Addr().Is4():
		return fmt.Errorf("must be an IPv4 loopback address (the listener is IPv4-only), got %q", ap.Addr())
	}
	return nil
}

// ValidateMetricsAddress validates address for the metrics
func ValidateAddress(addr string) error {
	_, port, err := net.SplitHostPort(addr)
	if err != nil || port == "" {
		return fmt.Errorf("expected host:port")
	}

	p, err := strconv.Atoi(port)
	if err != nil {
		return fmt.Errorf("port must be a number")
	}
	if p <= 0 {
		return fmt.Errorf("expected positive port number")
	}

	return nil
}
