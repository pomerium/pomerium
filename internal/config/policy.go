package config // import "github.com/pomerium/pomerium/internal/config"

import (
	"errors"
	"fmt"
	"net/url"
	"time"

	"github.com/pomerium/pomerium/internal/urlutil"
)

// Policy contains route specific configuration and access settings.
type Policy struct {
	From string `mapstructure:"from" yaml:"from"`
	To   string `mapstructure:"to" yaml:"to"`
	// Identity related policy
	AllowedEmails  []string `mapstructure:"allowed_users" yaml:"allowed_users"`
	AllowedGroups  []string `mapstructure:"allowed_groups" yaml:"allowed_groups"`
	AllowedDomains []string `mapstructure:"allowed_domains" yaml:"allowed_domains"`

	Source      *url.URL
	Destination *url.URL

	// Allow unauthenticated HTTP OPTIONS requests as per the CORS spec
	// https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS#Preflighted_requests
	CORSAllowPreflight bool `mapstructure:"cors_allow_preflight" yaml:"cors_allow_preflight"`

	// Allow any public request to access this route. **Bypasses authentication**
	AllowPublicUnauthenticatedAccess bool `mapstructure:"allow_public_unauthenticated_access" yaml:"allow_public_unauthenticated_access"`

	// UpstreamTimeout is the route specific timeout. Must be less than the global
	// timeout. If unset,  route will fallback to the proxy's DefaultUpstreamTimeout.
	UpstreamTimeout time.Duration `mapstructure:"timeout" yaml:"timeout"`

	// Enable proxying of websocket connections by removing the default timeout handler.
	// Caution: Enabling this feature could result in abuse via DOS attacks.
	AllowWebsockets bool `mapstructure:"allow_websockets"  yaml:"allow_websockets"`

	// TLSSkipVerify controls whether a client verifies the server's certificate
	// chain and host name.
	// If TLSSkipVerify is true, TLS accepts any certificate presented by the
	// server and any host name in that certificate.
	// In this mode, TLS is susceptible to man-in-the-middle attacks.
	// This should be used only for testing.
	TLSSkipVerify bool `mapstructure:"tls_skip_verify" yaml:"tls_skip_verify"`

	// TLSCustomCA defines the  root certificate to use with a given
	// route when verifying server certificates.
	TLSCustomCA string `mapstructure:"tls_custom_ca" yaml:"tls_custom_ca"`
}

// Validate checks the validity of a policy.
func (p *Policy) Validate() error {
	var err error
	p.Source, err = urlutil.ParseAndValidateURL(p.From)
	if err != nil {
		return fmt.Errorf("internal/config: bad source url %s", err)
	}

	p.Destination, err = urlutil.ParseAndValidateURL(p.To)
	if err != nil {
		return fmt.Errorf("internal/config: bad destination url %s", err)
	}

	// Only allow public access if no other whitelists are in place
	if p.AllowPublicUnauthenticatedAccess && (p.AllowedDomains != nil || p.AllowedGroups != nil || p.AllowedEmails != nil) {
		return errors.New("internal/config: route marked as public but contains whitelists")
	}

	return nil
}
