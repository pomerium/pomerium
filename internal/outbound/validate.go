package outbound

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"slices"
	"strconv"
	"strings"
)

// proxySchemes are the schemes a proxy URL may have.
var proxySchemes = []string{"http", "https", "socks5", "socks5h"}

// validateProxyURL returns an error if rawURL is not a usable proxy
// URL. Like HTTP_PROXY, a value without a scheme is an http proxy. The error
// does not include any part of rawURL, which may contain credentials.
func validateProxyURL(rawURL string) error {
	if rawURL == "" {
		return nil
	}
	if !strings.Contains(rawURL, "://") {
		rawURL = "http://" + rawURL
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		// url.Parse errors can quote parts of the credentials.
		if strings.Contains(rawURL, "@") {
			return errors.New("not a valid URL (special characters in credentials must be percent-encoded)")
		}
		return errors.New("not a valid URL")
	}
	if !slices.Contains(proxySchemes, u.Scheme) {
		return fmt.Errorf("unsupported proxy scheme (supported: %s)", strings.Join(proxySchemes, ", "))
	}
	return validateProxyURLParts(u)
}

// validateProxyURLParts returns an error if the parsed proxy URL u has
// a missing or invalid host, an invalid port, or a path other than "/", a
// query or a fragment. The error does not include any part of u.
func validateProxyURLParts(u *url.URL) error {
	if u.Hostname() == "" {
		return errors.New("missing proxy host")
	}
	if port := u.Port(); port != "" {
		if n, err := strconv.ParseUint(port, 10, 16); err != nil || n == 0 {
			return errors.New("invalid proxy port")
		}
	}
	// netip.ParseAddr accepts an IPv6 address with a zone.
	if _, err := netip.ParseAddr(u.Hostname()); err != nil && !isHostNameOrIP(u.Hostname()) {
		return errors.New("invalid proxy host")
	}
	if (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" {
		return errors.New("proxy URL must not have a path, query or fragment")
	}
	return nil
}

// validateNoProxy returns an error naming the first entry of a
// NO_PROXY style list that httpproxy would parse into a matcher that never
// matches a request host, or would ignore. Entries are parsed the same way:
// trimmed, lower-cased, then tried as "*", a CIDR range, an IP address with an
// optional port, or a domain name with an optional port.
func validateNoProxy(noProxy string) error {
	for entry := range strings.SplitSeq(noProxy, ",") {
		entry = strings.ToLower(strings.TrimSpace(entry))
		if entry == "" || entry == "*" {
			continue
		}
		if _, _, err := net.ParseCIDR(entry); err == nil {
			continue
		}
		if err := validateNoProxyHostPort(entry); err != nil {
			return fmt.Errorf("entry %q: %w", entry, err)
		}
	}
	return nil
}

func validateNoProxyHostPort(entry string) error {
	host, port, err := net.SplitHostPort(entry)
	if err != nil {
		host = entry
	}
	if strings.Trim(port, "0123456789") != "" {
		return errors.New("port must be a number")
	}
	if host == "" {
		return errors.New("missing host")
	}
	host = strings.TrimPrefix(host, "*.")
	if strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") {
		host = host[1 : len(host)-1]
	}
	if !isHostNameOrIP(host) {
		return errors.New("must be a host name, domain suffix, IP address or CIDR range, separated by commas")
	}
	return nil
}

// isHostNameOrIP reports whether host is an IP address or consists only of
// host name characters. Non-ASCII characters are left to IDNA conversion.
func isHostNameOrIP(host string) bool {
	if net.ParseIP(host) != nil {
		return true
	}
	notHostNameChar := func(c rune) bool {
		return c < 0x80 && !strings.ContainsRune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._", c)
	}
	return strings.IndexFunc(host, notHostNameChar) < 0
}
