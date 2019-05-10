package main // import "github.com/pomerium/pomerium/cmd/pomerium"

import (
	"errors"
	"fmt"
	"time"

	"github.com/pomerium/envconfig"
)

// Options are the global environmental flags used to set up pomerium's services.
// If a base64 encoded certificate and key are not provided as environmental variables,
// or if a file location is not provided, the server will attempt to find a matching keypair
// in the local directory as `./cert.pem` and `./privkey.pem` respectively.
type Options struct {
	// Debug outputs human-readable logs to Stdout.
	Debug bool `envconfig:"POMERIUM_DEBUG"`

	// LogLevel sets the global override for log level. All Loggers will use at least this value.
	// Possible options are "info","warn", and "error". Defaults to "debug".
	LogLevel string `envconfig:"LOG_LEVEL"`

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

	// HttpRedirectAddr, if set, specifies the host and port to run the HTTP
	// to HTTPS redirect server on. For example, ":http" would start a server
	// on port 80.  If empty, no redirect server is started.
	HTTPRedirectAddr string `envconfig:"HTTP_REDIRECT_ADDR"`

	// Timeout settings : https://github.com/pomerium/pomerium/issues/40
	ReadTimeout       time.Duration `envconfig:"TIMEOUT_READ"`
	WriteTimeout      time.Duration `envconfig:"TIMEOUT_WRITE"`
	ReadHeaderTimeout time.Duration `envconfig:"TIMEOUT_READ_HEADER"`
	IdleTimeout       time.Duration `envconfig:"TIMEOUT_IDLE"`
}

var defaultOptions = &Options{
	Debug:    false,
	LogLevel: "debug",
	Services: "all",
}

// optionsFromEnvConfig builds the main binary's configuration
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
func isValidService(s string) bool {
	switch s {
	case
		"all",
		"proxy",
		"authorize",
		"authenticate":
		return true
	}
	return false
}

func isAuthenticate(s string) bool {
	switch s {
	case
		"all",
		"authenticate":
		return true
	}
	return false
}

func isAuthorize(s string) bool {
	switch s {
	case
		"all",
		"authorize":
		return true
	}
	return false
}

func isProxy(s string) bool {
	switch s {
	case
		"all",
		"proxy":
		return true
	}
	return false
}
