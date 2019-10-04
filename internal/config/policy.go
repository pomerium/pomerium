package config // import "github.com/pomerium/pomerium/internal/config"

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/url"
	"time"

	"github.com/pomerium/pomerium/internal/cryptutil"
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

	// TLSServerName overrides the hostname in the `to` field. This is useful
	// if your backend is an HTTPS server with a valid certificate, but you
	// want to communicate to the backend with an internal hostname (e.g.
	// Docker container name).
	TLSServerName string `mapstructure:"tls_server_name" yaml:"tls_server_name"`

	// TLSCustomCA defines the  root certificate to use with a given
	// route when verifying server certificates.
	TLSCustomCA     string `mapstructure:"tls_custom_ca" yaml:"tls_custom_ca"`
	TLSCustomCAFile string `mapstructure:"tls_custom_ca_file" yaml:"tls_custom_ca_file"`
	RootCAs         *x509.CertPool

	// Contains the x.509 client certificate to to present to the downstream
	// host.
	TLSClientCert     string `mapstructure:"tls_client_cert" yaml:"tls_client_cert"`
	TLSClientKey      string `mapstructure:"tls_client_key" yaml:"tls_client_key"`
	TLSClientCertFile string `mapstructure:"tls_client_cert_file" yaml:"tls_client_cert_file"`
	TLSClientKeyFile  string `mapstructure:"tls_client_key_file" yaml:"tls_client_key_file"`
	ClientCertificate *tls.Certificate

	// SetRequestHeaders adds a collection of headers to the downstream request
	// in the form of key value pairs. Note bene, this will overwrite the
	// value of any existing value of a given header key.
	SetRequestHeaders map[string]string `mapstructure:"set_request_headers" yaml:"set_request_headers"`
}

// Validate checks the validity of a policy.
func (p *Policy) Validate() error {
	var err error
	p.Source, err = urlutil.ParseAndValidateURL(p.From)
	if err != nil {
		return fmt.Errorf("internal/config: policy bad source url %s", err)
	}

	p.Destination, err = urlutil.ParseAndValidateURL(p.To)
	if err != nil {
		return fmt.Errorf("internal/config: policy bad destination url %s", err)
	}

	// Only allow public access if no other whitelists are in place
	if p.AllowPublicUnauthenticatedAccess && (p.AllowedDomains != nil || p.AllowedGroups != nil || p.AllowedEmails != nil) {
		return fmt.Errorf("internal/config: policy route marked as public but contains whitelists")
	}

	if (p.TLSClientCert == "" && p.TLSClientKey != "") || (p.TLSClientCert != "" && p.TLSClientKey == "") ||
		(p.TLSClientCertFile == "" && p.TLSClientKeyFile != "") || (p.TLSClientCertFile != "" && p.TLSClientKeyFile == "") {
		return fmt.Errorf("internal/config: client certificate key and cert both must be non-empty")
	}

	if p.TLSClientCert != "" && p.TLSClientKey != "" {
		p.ClientCertificate, err = cryptutil.CertifcateFromBase64(p.TLSClientCert, p.TLSClientKey)
		if err != nil {
			return fmt.Errorf("internal/config: couldn't decode client cert %v", err)
		}
	} else if p.TLSClientCertFile != "" && p.TLSClientKeyFile != "" {
		p.ClientCertificate, err = cryptutil.CertificateFromFile(p.TLSClientCertFile, p.TLSClientKeyFile)
		if err != nil {
			return fmt.Errorf("internal/config: couldn't load client cert file %v", err)
		}
	}

	if p.TLSCustomCA != "" {
		p.RootCAs, err = cryptutil.CertPoolFromBase64(p.TLSCustomCA)
		if err != nil {
			return fmt.Errorf("internal/config: couldn't decode custom ca %v", err)
		}
	} else if p.TLSCustomCAFile != "" {
		p.RootCAs, err = cryptutil.CertPoolFromFile(p.TLSCustomCAFile)
		if err != nil {
			return fmt.Errorf("internal/config: couldn't load custom ca file %v", err)
		}
	}

	return nil
}
func (p *Policy) String() string {
	if p.Source == nil || p.Destination == nil {
		return fmt.Sprintf("%s → %s", p.From, p.To)
	}
	return fmt.Sprintf("%s → %s", p.Source.String(), p.Destination.String())
}
