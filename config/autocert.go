package config

// AutocertOptions contains the options to control the behavior of autocert.
type AutocertOptions struct {
	// Enable enables fully automated certificate management including issuance
	// and renewal from LetsEncrypt. Must be used in conjunction with Folder.
	Enable bool `mapstructure:"autocert" yaml:"autocert,omitempty"`

	// UseStaging tells autocert to use Let's Encrypt's staging CA which
	// has less strict usage limits then the (default) production CA.
	//
	// https://letsencrypt.org/docs/staging-environment/
	UseStaging bool `mapstructure:"autocert_use_staging" yaml:"autocert_use_staging,omitempty"`

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
}
