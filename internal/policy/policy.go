package policy // import "github.com/pomerium/pomerium/internal/policy"

import (
	"errors"
	"fmt"
	"io/ioutil"
	"net/url"
	"strings"
	"time"

	"github.com/pomerium/pomerium/internal/fileutil"
	yaml "gopkg.in/yaml.v2"
)

// Policy contains authorization policy information.
// todo(bdd) : add upstream timeout and configuration settings
type Policy struct {
	//
	From string `yaml:"from"`
	To   string `yaml:"to"`
	// Identity related policy
	AllowedEmails  []string `yaml:"allowed_users"`
	AllowedGroups  []string `yaml:"allowed_groups"`
	AllowedDomains []string `yaml:"allowed_domains"`

	Source      *url.URL
	Destination *url.URL

	// Allow unauthenticated HTTP OPTIONS requests as per the CORS spec
	// https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS#Preflighted_requests
	CORSAllowPreflight bool `yaml:"cors_allow_preflight"`

	// Allow any public request to access this route. **Bypasses authentication**
	AllowPublicUnauthenticatedAccess bool `yaml:"allow_public_unauthenticated_access"`

	// UpstreamTimeout is the route specific timeout. Must be less than the global
	// timeout. If unset,  route will fallback to the proxy's DefaultUpstreamTimeout.
	UpstreamTimeout time.Duration `yaml:"timeout"`
}

func (p *Policy) validate() (err error) {
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

// FromConfig parses configuration file as bytes and returns authorization
// policies. Supports yaml, json.
func FromConfig(confBytes []byte) ([]Policy, error) {
	var f []Policy
	if err := yaml.Unmarshal(confBytes, &f); err != nil {
		return nil, err
	}
	// build source and destination urls
	for i := range f {
		if err := (&f[i]).validate(); err != nil {
			return nil, fmt.Errorf("route at index %d: %v", i, err)
		}
	}
	return f, nil
}

// FromConfigFile parses configuration file from a path and returns
// authorization policies. Supports yaml, json.
func FromConfigFile(f string) ([]Policy, error) {
	exists, err := fileutil.IsReadableFile(f)
	if err != nil || !exists {
		return nil, fmt.Errorf("policy file %v: %v exists? %v", f, err, exists)
	}
	confBytes, err := ioutil.ReadFile(f)
	if err != nil {
		return nil, err
	}
	return FromConfig(confBytes)
}

// urlParse wraps url.Parse to add a scheme if none-exists.
// https://github.com/golang/go/issues/12585
func urlParse(uri string) (*url.URL, error) {
	if !strings.Contains(uri, "://") {
		uri = fmt.Sprintf("https://%s", uri)
	}
	return url.ParseRequestURI(uri)
}
