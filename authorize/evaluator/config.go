package evaluator

import (
	"sync"

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

	cacheKeyOnce     sync.Once
	computedCacheKey uint64
}

// cacheKey() returns a hash over the configuration, except for the policies.
func (e *evaluatorConfig) cacheKey() uint64 {
	e.cacheKeyOnce.Do(func() {
		e.computedCacheKey = hashutil.MustHash(e)
	})
	return e.computedCacheKey
}

// An Option customizes the evaluator config.
type Option func(*evaluatorConfig)

func (e *evaluatorConfig) apply(options ...Option) {
	for _, opt := range options {
		opt(e)
	}
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
