package evaluator

import (
	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/hashutil"
)

type evaluatorConfig struct {
	Policies                                          []*config.Policy `hash:"-"`
	ClientCA                                          []byte
	ClientCRL                                         []byte
	AddDefaultClientCertificateRule                   bool
	ClientCertConstraints                             ClientCertConstraints
	SigningKey                                        []byte
	AuthenticateURL                                   string
	GoogleCloudServerlessAuthenticationServiceAccount string
	JWTClaimsHeaders                                  config.JWTClaimHeaders
	JWTGroupsFilter                                   config.JWTGroupsFilter
	DefaultJWTIssuerFormat                            config.JWTIssuerFormat
}

// cacheKey() returns a hash over the configuration, except for the policies.
func (e *evaluatorConfig) cacheKey() uint64 {
	return hashutil.MustHash(e)
}

// An Option customizes the evaluator config.
type Option func(*evaluatorConfig)

func getConfig(options ...Option) *evaluatorConfig {
	cfg := new(evaluatorConfig)
	for _, o := range options {
		o(cfg)
	}
	return cfg
}

// WithPolicies sets the policies in the config.
func WithPolicies(policies []*config.Policy) Option {
	return func(cfg *evaluatorConfig) {
		cfg.Policies = policies
	}
}

// WithClientCA sets the client CA in the config.
func WithClientCA(clientCA []byte) Option {
	return func(cfg *evaluatorConfig) {
		cfg.ClientCA = clientCA
	}
}

// WithClientCRL sets the client CRL in the config.
func WithClientCRL(clientCRL []byte) Option {
	return func(cfg *evaluatorConfig) {
		cfg.ClientCRL = clientCRL
	}
}

// WithAddDefaultClientCertificateRule sets whether to add a default
// invalid_client_certificate deny rule to all policies.
func WithAddDefaultClientCertificateRule(addDefaultClientCertificateRule bool) Option {
	return func(cfg *evaluatorConfig) {
		cfg.AddDefaultClientCertificateRule = addDefaultClientCertificateRule
	}
}

// WithClientCertConstraints sets addition client certificate constraints.
func WithClientCertConstraints(constraints *ClientCertConstraints) Option {
	return func(cfg *evaluatorConfig) {
		cfg.ClientCertConstraints = *constraints
	}
}

// WithSigningKey sets the signing key and algorithm in the config.
func WithSigningKey(signingKey []byte) Option {
	return func(cfg *evaluatorConfig) {
		cfg.SigningKey = signingKey
	}
}

// WithAuthenticateURL sets the authenticate URL in the config.
func WithAuthenticateURL(authenticateURL string) Option {
	return func(cfg *evaluatorConfig) {
		cfg.AuthenticateURL = authenticateURL
	}
}

// WithGoogleCloudServerlessAuthenticationServiceAccount sets the google cloud serverless authentication service
// account in the config.
func WithGoogleCloudServerlessAuthenticationServiceAccount(serviceAccount string) Option {
	return func(cfg *evaluatorConfig) {
		cfg.GoogleCloudServerlessAuthenticationServiceAccount = serviceAccount
	}
}

// WithJWTClaimsHeaders sets the JWT claims headers in the config.
func WithJWTClaimsHeaders(headers config.JWTClaimHeaders) Option {
	return func(cfg *evaluatorConfig) {
		cfg.JWTClaimsHeaders = headers
	}
}

// WithJWTGroupsFilter sets the JWT groups filter in the config.
func WithJWTGroupsFilter(groups config.JWTGroupsFilter) Option {
	return func(cfg *evaluatorConfig) {
		cfg.JWTGroupsFilter = groups
	}
}

// WithDefaultJWTIssuerFormat sets the default JWT issuer format in the config.
func WithDefaultJWTIssuerFormat(format config.JWTIssuerFormat) Option {
	return func(cfg *evaluatorConfig) {
		cfg.DefaultJWTIssuerFormat = format
	}
}
