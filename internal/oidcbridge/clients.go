package oidcbridge

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"net/url"
	"path"
	"regexp"
	"strings"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/urlutil"
)

type ClientInfo struct {
	// ID is the client_id string.
	ID string

	// RedirectURI is the validated redirect_uri.
	RedirectURI string

	// SecretHash is the SHA-256 hash of the client_secret (if one was set), or
	// nil for a "public" client.
	SecretHash []byte
}

var urlHostnameRegexp = regexp.MustCompile("^[a-zA-Z0-9.-]+$")

// parseURL parses a client_id or redirect_uri URL. To be considered valid, a
// URL must:
//   - have the scheme "https"
//   - not contain a username/password
//   - have a hostname that is plausibly a domain
//   - not contain a query
//   - not contain a fragment
//   - not contain empty or relative path components
func parseURL(originalURL string) (*url.URL, error) {
	cleanPath := func(p string) string {
		if p == "" || p == "/" {
			return p
		}
		cleaned := path.Clean(p)
		if cleaned != "/" && strings.HasSuffix(p, "/") {
			return cleaned + "/"
		}
		return cleaned
	}

	u, err := url.Parse(originalURL)
	if err != nil {
		return nil, err
	} else if u.Scheme != "https" {
		return nil, fmt.Errorf(`URL scheme must be "https"`)
	} else if u.User != nil {
		return nil, fmt.Errorf("URL must not contain a username or password")
	} else if !urlHostnameRegexp.MatchString(u.Hostname()) {
		return nil, fmt.Errorf("invalid URL hostname")
	} else if u.RawQuery != "" {
		return nil, fmt.Errorf("URL must not contain query parameters")
	} else if u.Fragment != "" {
		return nil, fmt.Errorf("URL must not contain a fragment")
	} else if cleaned := (&url.URL{
		Scheme: "https",
		Host:   u.Host,
		Path:   cleanPath(u.Path),
	}).String(); cleaned != originalURL {
		return nil, fmt.Errorf("invalid URL path")
	}
	return u, nil
}

// ClientLookup is an indexed view of the routes with the OIDCBridge option set.
type ClientLookup struct {
	// Routes keyed by "From" URL host.
	nonWildcardRoutes map[string][]*config.Policy

	// List of all wildcard "From" URL clients.
	wildcardRoutes []*config.Policy

	// Global options (needed for defaults + runtime flags).
	globalOptions *config.Options
}

// buildForConfig rebuilds the ClientLookup for the provided configuration.
func (c *ClientLookup) buildForConfig(o *config.Options) {
	c.nonWildcardRoutes = make(map[string][]*config.Policy)
	c.wildcardRoutes = make([]*config.Policy, 0)
	c.globalOptions = o

	// Index all of the routes with the OIDCBridge option set.
	for r := range o.GetAllPolicies() {
		if !o.GetOIDCBridgeForPolicy(r).IsEnabled() {
			continue
		}

		fromURL, err := urlutil.ParseAndValidateURL(r.From)
		if err != nil {
			// Config validation is performed separately, so this branch should
			// never be hit in practice.
			continue
		}

		// TODO: refactor out a helper method to keep this in sync with the envoyconfig code
		host := fromURL.Host
		hasWildcard := strings.Contains(host, "*")
		if !hasWildcard {
			c.nonWildcardRoutes[host] = append(c.nonWildcardRoutes[host], r)
		} else {
			c.wildcardRoutes = append(c.wildcardRoutes, r)
		}
	}
}

func (c *ClientLookup) Empty() bool {
	return len(c.nonWildcardRoutes) == 0 && len(c.wildcardRoutes) == 0
}

// Lookup returns the ClientInfo for the given clientID and redirectURI, or an
// error if these parameters are not valid.
func (c *ClientLookup) Lookup(clientID, redirectURI string) (*ClientInfo, error) {
	if clientID == "" {
		return nil, errors.New("missing client_id")
	} else if redirectURI == "" {
		return nil, errors.New("missing redirect_uri")
	}

	parsedClient, err := parseURL(clientID)
	if err != nil {
		return nil, fmt.Errorf("invalid client_id: %w", err)
	}
	parsedRedirect, err := parseURL(redirectURI)
	if err != nil {
		return nil, fmt.Errorf("invalid redirect_uri: %w", err)
	}
	if !redirectURIMatches(parsedClient, parsedRedirect) {
		return nil, fmt.Errorf("redirect_uri %q does not match client_id %q", redirectURI, clientID)
	}

	var routesToScan []*config.Policy
	if routes, ok := c.nonWildcardRoutes[parsedClient.Host]; ok {
		routesToScan = routes
	} else {
		routesToScan = c.wildcardRoutes
	}

	stripPort := c.globalOptions.IsRuntimeFlagSet(config.RuntimeFlagMatchAnyIncomingPort)

	for _, r := range routesToScan {
		clientMatches := r.Matches(parsedClient, stripPort)
		redirectMatches := r.Matches(parsedRedirect, stripPort)
		if clientMatches && redirectMatches {
			info := ClientInfo{
				ID:          clientID,
				RedirectURI: redirectURI,
			}
			oidcBridge := c.globalOptions.GetOIDCBridgeForPolicy(r)
			if oidcBridge.ClientSecret.IsSet {
				// Store a hash of the explicit client_secret, so we can perform
				// a constant-time string comparison during verification.
				hash := sha256.Sum256([]byte(oidcBridge.ClientSecret.Value))
				info.SecretHash = hash[:]
			}
			return &info, nil
		} else if clientMatches || redirectMatches {
			return nil, fmt.Errorf("redirect_uri %q does not match client_id route", redirectURI)
		}
	}
	return nil, errors.New("unknown client_id")
}

// redirectURIMatches returns whether redirect is equal to or a "child" path of client.
func redirectURIMatches(client, redirect *url.URL) bool {
	// The host must match exactly.
	if redirect.Host != client.Host {
		return false
	}
	// The path must either match exactly, or the redirect_uri must be a sub-path.
	if redirect.Path == client.Path {
		return true
	}
	remainder, ok := strings.CutPrefix(redirect.Path, client.Path)
	return ok && (strings.HasSuffix(client.Path, "/") || strings.HasPrefix(remainder, "/"))
}
