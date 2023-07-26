package evaluator

import (
	"github.com/pomerium/pomerium/config"
)

type evaluatorConfig struct {
	policies                                          []config.Policy
	clientCA                                          []byte
	signingKey                                        []byte
	authenticateURL                                   string
	googleCloudServerlessAuthenticationServiceAccount string
	jwtClaimsHeaders                                  config.JWTClaimHeaders
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
func WithPolicies(policies []config.Policy) Option {
	return func(cfg *evaluatorConfig) {
		cfg.policies = policies
	}
}

// WithClientCA sets the client CA in the config.
func WithClientCA(clientCA []byte) Option {
	return func(cfg *evaluatorConfig) {
		cfg.clientCA = clientCA
	}
}

// WithSigningKey sets the signing key and algorithm in the config.
func WithSigningKey(signingKey []byte) Option {
	return func(cfg *evaluatorConfig) {
		cfg.signingKey = signingKey
	}
}

// WithAuthenticateURL sets the authenticate URL in the config.
func WithAuthenticateURL(authenticateURL string) Option {
	return func(cfg *evaluatorConfig) {
		cfg.authenticateURL = authenticateURL
	}
}

// WithGoogleCloudServerlessAuthenticationServiceAccount sets the google cloud serverless authentication service
// account in the config.
func WithGoogleCloudServerlessAuthenticationServiceAccount(serviceAccount string) Option {
	return func(cfg *evaluatorConfig) {
		cfg.googleCloudServerlessAuthenticationServiceAccount = serviceAccount
	}
}

// WithJWTClaimsHeaders sets the JWT claims headers in the config.
func WithJWTClaimsHeaders(headers config.JWTClaimHeaders) Option {
	return func(cfg *evaluatorConfig) {
		cfg.jwtClaimsHeaders = headers
	}
}
