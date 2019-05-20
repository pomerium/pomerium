package policy // import "github.com/pomerium/pomerium/internal/policy"

import (
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"
)

// Policy contains authorization policy information.
// todo(bdd) : add upstream timeout and configuration settings
type Policy struct {
	//
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
}

// Validate parses the source and destination URLs in the Policy
func (p *Policy) Validate() (err error) {
	p.Source, err = urlParse(p.From)
	if err != nil {
		return err
	}

	p.Destination, err = urlParse(p.To)
	if err != nil {
		return err
	}

	// Only allow public access if no other whitelists are in place
	if p.AllowPublicUnauthenticatedAccess && (p.AllowedDomains != nil || p.AllowedGroups != nil || p.AllowedEmails != nil) {
		return errors.New("route marked as public but contains whitelists")
	}

	return nil
}

// URLParse wraps url.Parse to add a scheme if none-exists.
// https://github.com/golang/go/issues/12585
func urlParse(uri string) (*url.URL, error) {
	if !strings.Contains(uri, "://") {
		uri = fmt.Sprintf("https://%s", uri)
	}
	return url.ParseRequestURI(uri)
}
