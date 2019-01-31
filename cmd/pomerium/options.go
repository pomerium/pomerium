package main // import "github.com/pomerium/pomerium/cmd/pomerium"

import (
	"errors"
	"fmt"

	"github.com/pomerium/envconfig"
)

// Options are the global environmental flags used to set up pomerium's services.
// If a base64 encoded certificate and key are not provided as environmental variables,
// or if a file location is not provided, the server will attempt to find a matching keypair
// in the local directory as `./cert.pem` and `./privkey.pem` respectively.
type Options struct {
	// Debug enables more verbose logging, and outputs human-readable logs to Stdout.
	// Set with POMERIUM_DEBUG
	Debug bool `envconfig:"POMERIUM_DEBUG"`

	// SharedKey is the shared secret authorization key used to mutually authenticate
	// requests between services.
	SharedKey string `envconfig:"SHARED_SECRET"`

	// Services is a list enabled service mode. If none are selected, "all" is used.
	// Available options are : "all", "authenticate", "proxy".
	Services string `envconfig:"SERVICES"`
	// Addr specifies the host and port on which the server should serve
	// HTTPS requests. If empty, ":https" is used.
	Addr string `envconfig:"ADDRESS"`
	// Cert and Key specifies the base64 encoded TLS certificates to use.
	Cert string `envconfig:"CERTIFICATE"`
	Key  string `envconfig:"CERTIFICATE_KEY"`
	// CertFile and KeyFile specifies the TLS certificates to use.
	CertFile string `envconfig:"CERTIFICATE_FILE"`
	KeyFile  string `envconfig:"CERTIFICATE_KEY_FILE"`
}

var defaultOptions = &Options{
	Debug:    false,
	Services: "all",
}

// optionsFromEnvConfig builds the IdentityProvider service's configuration
// options from provided environmental variables
func optionsFromEnvConfig() (*Options, error) {
	o := defaultOptions
	if err := envconfig.Process("", o); err != nil {
		return nil, err
	}
	if !isValidService(o.Services) {
		return nil, fmt.Errorf("%s is an invalid service type", o.Services)
	}
	if o.SharedKey == "" {
		return nil, errors.New("shared-key cannot be empty")
	}
	return o, nil
}

// isValidService checks to see if a service is a valid service mode
func isValidService(service string) bool {
	switch service {
	case
		"all",
		"proxy",
		"authenticate":
		return true
	}
	return false
}
