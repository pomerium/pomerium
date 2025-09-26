package oidc

import (
	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

type config struct {
	deviceAuthRequiresClientSecret bool
	getProvider                    func() (*oidc.Provider, error)
	getVerifier                    func(provider *oidc.Provider) *oidc.IDTokenVerifier
	getOauthConfig                 func(provider *oidc.Provider) *oauth2.Config
}

// An Option customizes the config.
type Option func(*config)

func getConfig(options ...Option) *config {
	cfg := &config{}
	for _, option := range options {
		option(cfg)
	}
	return cfg
}

// WithDeviceAuthRequiresClientSecret sets the device auth requires client secret option.
func WithDeviceAuthRequiresClientSecret(deviceAuthRequiresClientSecret bool) Option {
	return func(c *config) {
		c.deviceAuthRequiresClientSecret = deviceAuthRequiresClientSecret
	}
}

// WithGetOauthConfig sets the getOauthConfig function in the config.
func WithGetOauthConfig(f func(provider *oidc.Provider) *oauth2.Config) Option {
	return func(cfg *config) {
		cfg.getOauthConfig = f
	}
}

// WithGetProvider sets the getProvider function in the config.
func WithGetProvider(f func() (*oidc.Provider, error)) Option {
	return func(cfg *config) {
		cfg.getProvider = f
	}
}

// WithGetVerifier sets the getVerifier function in the config.
func WithGetVerifier(f func(*oidc.Provider) *oidc.IDTokenVerifier) Option {
	return func(cfg *config) {
		cfg.getVerifier = f
	}
}
