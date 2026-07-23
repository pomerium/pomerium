// Package ref parses and canonicalizes secret backend references.
//
// A Ref is the parsed form of a binding URL such as
// "file:///etc/pomerium/secrets/token#data.token". It exposes two derived
// keys used by the resolver:
//
//   - FetchKey() dedupes fetches/watches/singleflight on the canonical URL
//     WITHOUT the fragment, so N bindings selecting different fields of one
//     backend payload share a single fetch loop.
//   - Key() is the full value identity: the canonical URL WITH the fragment,
//     so each distinct selector yields a distinct cached value.
//
// A Ref carries only configuration (scheme, path, query, selector); it never
// holds secret material and is safe to log via String().
package ref

import (
	"errors"
	"fmt"
	"net/url"
	"strings"
)

// Ref is a parsed, canonicalizable secret backend reference.
type Ref struct {
	scheme   string
	url      *url.URL
	selector string
}

// Parse parses raw into a Ref, applying shape-only validation. Scheme
// registration and provider-specific parameter validation are the provider's
// responsibility (see pkg/secrets/provider).
func Parse(raw string) (Ref, error) {
	if raw == "" {
		return Ref{}, errors.New("secret ref: empty URL")
	}
	// No ${...} interpolation is permitted anywhere in a binding URL: URLs are
	// static config, never derived from request data.
	if strings.Contains(raw, "${") {
		return Ref{}, errors.New(`secret ref: URL must not contain "${...}" interpolation`)
	}

	u, err := url.Parse(raw)
	if err != nil {
		return Ref{}, fmt.Errorf("secret ref: invalid URL: %w", err)
	}

	scheme := strings.ToLower(u.Scheme)
	if scheme == "" {
		return Ref{}, errors.New("secret ref: URL must have a scheme")
	}
	u.Scheme = scheme

	// file:// URLs must be host-less absolute paths (stdlib/RFC 8089 semantics);
	// "file://relative/path" parses relative as an authority, which is invalid.
	if scheme == "file" {
		if u.Host != "" {
			return Ref{}, fmt.Errorf("secret ref: file URL must not have a host component (got %q)", u.Host)
		}
		if !strings.HasPrefix(u.Path, "/") {
			return Ref{}, errors.New("secret ref: file URL path must be absolute")
		}
	}

	// The fragment is the payload selector. A leading '/' is reserved for a
	// future RFC 6901 JSON-pointer form, so reject it now (D2).
	if strings.HasPrefix(u.Fragment, "/") {
		return Ref{}, errors.New(`secret ref: fragment selectors beginning with "/" are reserved`)
	}

	return Ref{scheme: scheme, url: u, selector: u.Fragment}, nil
}

// Scheme returns the lowercased URL scheme.
func (r Ref) Scheme() string { return r.scheme }

// URL returns a defensive copy of the parsed URL.
func (r Ref) URL() *url.URL {
	if r.url == nil {
		return nil
	}
	u := *r.url
	if r.url.User != nil {
		user := *r.url.User
		u.User = &user
	}
	return &u
}

// Selector returns the payload selector (the URL fragment), or "" if none.
func (r Ref) Selector() string { return r.selector }

// Key returns the full value identity: the canonical URL including fragment.
// Distinct selectors over the same backend produce distinct keys.
func (r Ref) Key() string { return r.canonical(true) }

// FetchKey returns the fetch/singleflight/watch dedupe key: the canonical URL
// excluding fragment. Refs differing only by selector share a FetchKey.
func (r Ref) FetchKey() string { return r.canonical(false) }

// String returns a display form safe to log; it never contains secret material
// because a Ref only ever holds configuration.
func (r Ref) String() string { return r.Key() }

// canonical renders a deterministic, canonicalized URL string. Query
// parameters are re-encoded via url.Values.Encode (sorted by key), the scheme
// is lowercased, and the fragment is canonically re-escaped or dropped.
func (r Ref) canonical(withFragment bool) string {
	if r.url == nil {
		return ""
	}
	u := *r.url
	u.Scheme = r.scheme
	if u.RawQuery != "" {
		u.RawQuery = u.Query().Encode()
	}
	if withFragment {
		u.Fragment = r.selector
		u.RawFragment = ""
	} else {
		u.Fragment = ""
		u.RawFragment = ""
	}
	return u.String()
}
