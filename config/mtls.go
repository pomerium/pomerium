package config

import (
	"context"
	"encoding/base64"
	"fmt"
	"os"

	"github.com/pomerium/pomerium/pkg/cryptutil"
	"github.com/pomerium/pomerium/pkg/grpc/config"
)

// DownstreamMTLSSettings specify the downstream client certificate requirements.
type DownstreamMTLSSettings struct {
	// CA is the base64-encoded certificate authority (or bundle of certificate
	// authorities) that should serve as the trust root(s). These will be
	// advertised in the initial TLS handshake.
	CA string `mapstructure:"ca" yaml:"ca"`

	// CAFile is the path to a file containing the certificate authority (or
	// bundle of certificate authorities) that should serve as the trust
	// root(s). These will be advertised in the initial TLS handshake.
	CAFile string `mapstructure:"ca_file" yaml:"ca_file"`

	// CRL is the base64-encoded certificate revocation list (or bundle of
	// CRLs) to use when validating client certificates.
	CRL string `mapstructure:"crl" yaml:"crl,omitempty"`

	// CRLFile is the path to a file containing the certificate revocation
	// list (or bundle of CRLs) to use when validating client certificates.
	CRLFile string `mapstructure:"crl_file" yaml:"crl_file,omitempty"`
}

// GetCA returns the certificate authority (or nil if unset).
func (s *DownstreamMTLSSettings) GetCA() ([]byte, error) {
	if s.CA != "" {
		return base64.StdEncoding.DecodeString(s.CA)
	}
	if s.CAFile != "" {
		return os.ReadFile(s.CAFile)
	}
	return nil, nil
}

// GetCRL returns the certificate revocation list bundle (or nil if unset).
func (s *DownstreamMTLSSettings) GetCRL() ([]byte, error) {
	if s.CRL != "" {
		return base64.StdEncoding.DecodeString(s.CRL)
	}
	if s.CRLFile != "" {
		return os.ReadFile(s.CRLFile)
	}
	return nil, nil
}

func (s *DownstreamMTLSSettings) validate() error {
	if s.CA != "" {
		if _, err := base64.StdEncoding.DecodeString(s.CA); err != nil {
			return fmt.Errorf("CA: %w", err)
		}
	}

	if s.CAFile != "" {
		if _, err := os.ReadFile(s.CAFile); err != nil {
			return fmt.Errorf("CA file: %w", err)
		}
	}

	if s.CRL != "" {
		if _, err := cryptutil.CRLFromBase64(s.CRL); err != nil {
			return fmt.Errorf("CRL: %w", err)
		}
	}

	if s.CRLFile != "" {
		if _, err := cryptutil.CRLFromFile(s.CRLFile); err != nil {
			return fmt.Errorf("CRL file: %w", err)
		}
	}

	return nil
}

func (s *DownstreamMTLSSettings) applySettingsProto(
	_ context.Context, p *config.DownstreamMtlsSettings,
) {
	if p == nil {
		return
	}
	set(&s.CA, p.Ca)
	set(&s.CRL, p.Crl)
}
