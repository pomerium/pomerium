package policy // import "github.com/pomerium/pomerium/internal/policy"

import (
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
	// proxy related
	From string `yaml:"from"`
	To   string `yaml:"to"`
	// upstream transport settings
	UpstreamTimeout time.Duration `yaml:"timeout"`
	// Identity related policy
	AllowedEmails  []string `yaml:"allowed_users"`
	AllowedGroups  []string `yaml:"allowed_groups"`
	AllowedDomains []string `yaml:"allowed_domains"`

	Source      *url.URL
	Destination *url.URL
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
			return nil, err
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
