package config

import (
	"fmt"
	"net"
	"strconv"
	"strings"

	goset "github.com/hashicorp/go-set/v3"
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

func (o *Options) ValidateTailscaleListenerSettings() error {
	if len(o.TailscaleListeners.Value) == 0 {
		return nil
	}

	seen := goset.New[string](0)
	for i, t := range o.TailscaleListeners.Value {
		if err := t.Validate(); err != nil {
			return fmt.Errorf("config: tailscale_listeners[%d]: %w", i, err)
		}
		if !seen.Insert(t.Hostname.Value) {
			return fmt.Errorf("config: tailscale_listeners[%d]: hostname must be unique across listeners", i)
		}
	}

	return nil
}

// Validate validates the tailscale listener settings.
func (s *TailscaleListenerSettings) Validate() error {
	if !s.AuthKey.IsSet && !s.OauthClientID.IsSet && !s.OauthClientSecret.IsSet && !s.IDToken.IsSet {
		return fmt.Errorf("tailscale_listener: auth_key, oauth_client_id, oauth_client_secret or id_token must be set")
	} else if s.AuthKey.IsSet && (s.OauthClientID.IsSet || s.OauthClientSecret.IsSet || s.IDToken.IsSet) {
		return fmt.Errorf("tailscale_listener: if auth_key is set, oauth_client_id, oauth_client_secret and id_token should not be set")
	}

	if s.Hostname.Or("") == "" {
		return fmt.Errorf("tailscale_listener: hostname must be non-empty")
	}

	return nil
}
