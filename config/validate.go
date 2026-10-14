package config

import (
	"fmt"
	"net"
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

// Validate validates the tailscale listener settings.
func (s *TailscaleListenerSettings) Validate() error {
	if !s.AuthKey.IsSet && !s.OauthClientID.IsSet && !s.IDToken.IsSet {
		return fmt.Errorf("tailscale_listener: auth_key, oauth_client_id or id_token must be set")
	} else if s.AuthKey.IsSet && (s.OauthClientID.IsSet || s.IDToken.IsSet) {
		return fmt.Errorf("tailscale_listener: if auth_key is set, oauth_client_id and id_token should not be set")
	} else if s.OauthClientID.IsSet && (s.AuthKey.IsSet || s.IDToken.IsSet) {
		return fmt.Errorf("tailscale_listener: if oauth_client_id is set, auth_key and id_token should not be set")
	} else if s.IDToken.IsSet && (s.AuthKey.IsSet || s.OauthClientID.IsSet) {
		return fmt.Errorf("tailscale_listener: if id_token is set, auth_key and oidc_client_id should not be set")
	}

	if s.OauthClientID.IsSet && !s.OauthClientSecret.IsSet {
		return fmt.Errorf("tailscale_listener: if oauth_client_id is set, oauth_client_secret must also be set")
	} else if s.OauthClientSecret.IsSet && !s.OauthClientID.IsSet {
		return fmt.Errorf("tailscale_listener: if oauth_client_secret is set, oauth_client_id must also be set")
	}

	if s.Hostname.Or("") == "" {
		return fmt.Errorf("tailscale_listener: hostname must be non-empty")
	}

	return nil
}
