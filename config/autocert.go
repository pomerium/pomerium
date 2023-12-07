package config

import (
	"encoding/base64"
	"errors"
	"fmt"
	"os"

	"github.com/pomerium/pomerium/pkg/cryptutil"
)

// AutocertOptions contains the options to control the behavior of autocert.
type AutocertOptions struct {
	// Enable enables fully automated certificate management including issuance
	// and renewal from LetsEncrypt. Must be used in conjunction with Folder.
	Enable bool `mapstructure:"autocert" yaml:"autocert,omitempty"`

	// CA is the directory URL of a CA supporting the ACME protocol to request
	// certificates from. This can be used to use an alternative CA than
	// Let's Encrypt. This setting overrules the UseStaging setting.
	CA string `mapstructure:"autocert_ca" yaml:"autocert_ca,omitempty"`

	// Email is the email address to use for account registration with the ACME CA.
	Email string `mapstructure:"autocert_email" yaml:"autocert_email,omitempty"`

	// UseStaging tells autocert to use Let's Encrypt's staging CA which
	// has less strict usage limits then the (default) production CA.
	//
	// https://letsencrypt.org/docs/staging-environment/
	UseStaging bool `mapstructure:"autocert_use_staging" yaml:"autocert_use_staging,omitempty"`

	// EABKeyID is an ASCII string identifier for the External Account Binding
	// key that must be used to request a new account with an ACME CA supporting
	// External Account Binding.
	EABKeyID string `mapstructure:"autocert_eab_key_id" yaml:"autocert_eab_key_id,omitempty"`

	// EABMACKey is a base64url-encoded secret key corresponding to the EABKeyID to use
	// when creating a new account with an ACME CA supporting External Account Binding.
	EABMACKey string `mapstructure:"autocert_eab_mac_key" yaml:"autocert_eab_mac_key,omitempty"`

	// MustStaple will cause autocert to request a certificate with
	// status_request extension. This will allow the TLS client (the browser)
	// to fail immediately if Pomerium failed to get an OCSP staple.
	// See also https://tools.ietf.org/html/rfc7633
	// Only used when Enable is true.
	MustStaple bool `mapstructure:"autocert_must_staple" yaml:"autocert_must_staple,omitempty"`

	// Folder specifies the location to store, and load autocert managed
	// TLS certificates.
	// defaults to $XDG_DATA_HOME/pomerium
	Folder string `mapstructure:"autocert_dir" yaml:"autocert_dir,omitempty"`

	// TrustedCA is the base64-encoded certificate (bundle) to trust when communicating with an ACME CA.
	TrustedCA string `mapstructure:"autocert_trusted_ca" yaml:"autocert_trusted_ca,omitempty"`

	// TrustedCAFile points to a file that contains the certificate (bundle) to trust when communicating with an ACME CA.
	TrustedCAFile string `mapstructure:"autocert_trusted_ca_file" yaml:"autocert_trusted_ca_file,omitempty"`
}

// Validate ensures the Options fields are valid, and hydrated.
func (o *AutocertOptions) Validate() error {
	// validate ACME EAB settings
	if o.EABKeyID != "" && o.EABMACKey == "" {
		return errors.New("config: Autocert EAB MAC Key required when Key ID is provided")
	}
	if o.EABKeyID == "" && o.EABMACKey != "" {
		return errors.New("config: Autocert EAB Key ID required when MAC Key is provided")
	}
	if o.EABMACKey != "" {
		if _, err := base64.RawURLEncoding.DecodeString(o.EABMACKey); err != nil {
			return fmt.Errorf("config: decoding base64-urlencoded MAC Key: %w", err)
		}
	}

	// validate x509 roots to trust
	if o.TrustedCA != "" && o.TrustedCAFile != "" {
		return errors.New("config: providing both Autocert Trusted CA and Trusted CA File is not supported")
	}
	if o.TrustedCA != "" {
		if _, err := base64.StdEncoding.DecodeString(o.TrustedCA); err != nil {
			return fmt.Errorf("config: decoding trusted certificate pool base64: %w", err)
		}
		if _, err := cryptutil.GetCertPool(o.TrustedCA, ""); err != nil {
			return fmt.Errorf("config: getting trusted certificate pool: %w", err)
		}
	}
	if o.TrustedCAFile != "" {
		if _, err := os.ReadFile(o.TrustedCAFile); err != nil {
			return fmt.Errorf("config: bad trusted certificate (bundle) file: %w", err)
		}
		if _, err := cryptutil.GetCertPool("", o.TrustedCAFile); err != nil {
			return fmt.Errorf("config: getting trusted certificate pool: %w", err)
		}
	}

	return nil
}
