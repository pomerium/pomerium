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
		ca, err := base64.StdEncoding.DecodeString(s.CA)
		if err != nil {
			return nil, fmt.Errorf("CA: %w", err)
		}
		return ca, nil
	}
	if s.CAFile != "" {
		ca, err := os.ReadFile(s.CAFile)
		if err != nil {
			return nil, fmt.Errorf("CA file: %w", err)
		}
		return ca, nil
	}
	return nil, nil
}

// GetCRL returns the certificate revocation list bundle (or nil if unset).
func (s *DownstreamMTLSSettings) GetCRL() ([]byte, error) {
	if s.CRL != "" {
		crl, err := base64.StdEncoding.DecodeString(s.CRL)
		if err != nil {
			return nil, fmt.Errorf("CRL: %w", err)
		}
		return crl, nil
	}
	if s.CRLFile != "" {
		crl, err := os.ReadFile(s.CRLFile)
		if err != nil {
			return nil, fmt.Errorf("CRL file: %w", err)
		}
		return crl, nil
	}
	return nil, nil
}

func (s *DownstreamMTLSSettings) validate() error {
	if _, err := s.GetCA(); err != nil {
		return err
	}

	crl, err := s.GetCRL()
	if err != nil {
		return err
	}
	if len(crl) > 0 {
		if _, err := cryptutil.DecodeCRL(crl); err != nil {
			return fmt.Errorf("CRL: %w", err)
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
