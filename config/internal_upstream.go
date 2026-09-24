package config

import (
	"fmt"
	"net/url"
)

// InternalUpstreamScheme is the `to` scheme that names a service Pomerium runs
// itself rather than an external upstream. Such a service listens on an
// allocated loopback port nobody can know in advance, so a route names it
// instead, and the Envoy config resolves the name to that port.
//
// The set of names is closed: a route can only reach what is listed here.
const InternalUpstreamScheme = "pomerium"

// InternalUpstreamAgentic names the agentic authorization server. Its
// endpoints are authorized only by the routes pointing at it.
const InternalUpstreamAgentic = "agentic"

// IsInternalUpstream reports whether u names a service Pomerium runs itself.
func IsInternalUpstream(u *url.URL) bool {
	return u.Scheme == InternalUpstreamScheme
}

// validateInternalUpstream accepts exactly pomerium://<name> for a known name:
// no port, path, query or credentials, since none of them would mean anything.
func validateInternalUpstream(u *url.URL) error {
	switch {
	case u.User != nil || u.Port() != "" || (u.Path != "" && u.Path != "/") ||
		u.RawQuery != "" || u.Fragment != "":
		return fmt.Errorf("%s:// upstreams take a bare service name, e.g. %s://%s",
			InternalUpstreamScheme, InternalUpstreamScheme, InternalUpstreamAgentic)
	case u.Hostname() != InternalUpstreamAgentic:
		return fmt.Errorf("unknown %s:// upstream %q", InternalUpstreamScheme, u.Hostname())
	}
	return nil
}
