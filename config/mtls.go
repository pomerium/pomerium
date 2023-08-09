package config

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"os"

	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/pkg/cryptutil"
	"github.com/pomerium/pomerium/pkg/grpc/config"
)

// MTLSEnforcement represents a client certificate enforcement behavior.
type MTLSEnforcement string

const (
	// MTLSEnforcementPolicy specifies no default client certificate
	// enforcement: any requirements must be explicitly specified in a policy.
	MTLSEnforcementPolicy MTLSEnforcement = "policy"

	// MTLSEnforcementPolicyWithDefaultDeny specifies that client certificate
	// requirements will be enforced by route policy, with a default
	// invalid_client_certificate deny rule added to each policy.
	MTLSEnforcementPolicyWithDefaultDeny MTLSEnforcement = "policy_with_default_deny"

	// MTLSEnforcementRejectConnection specifies that client certificate
	// requirements will be enforced by rejecting any connection attempts
	// without a trusted certificate.
	MTLSEnforcementRejectConnection MTLSEnforcement = "reject_connection"
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

	// Enforcement indicates the behavior applied to requests without a valid
	// client certificate.
	Enforcement MTLSEnforcement `mapstructure:"enforcement" yaml:"enforcement,omitempty"`
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

// GetEnforcement returns the enforcement behavior to apply.
func (s *DownstreamMTLSSettings) GetEnforcement() MTLSEnforcement {
	if s.Enforcement == "" {
		return MTLSEnforcementPolicyWithDefaultDeny
	}
	return s.Enforcement
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

	switch s.Enforcement {
	case "",
		MTLSEnforcementPolicy,
		MTLSEnforcementPolicyWithDefaultDeny,
		MTLSEnforcementRejectConnection: // OK
	default:
		return errors.New("unknown enforcement option")
	}

	return nil
}

func (s *DownstreamMTLSSettings) applySettingsProto(
	ctx context.Context, p *config.DownstreamMtlsSettings,
) {
	if p == nil {
		return
	}
	set(&s.CA, p.Ca)
	set(&s.CRL, p.Crl)
	s.Enforcement = mtlsEnforcementFromProtoEnum(ctx, p.Enforcement)
}

func mtlsEnforcementFromProtoEnum(
	ctx context.Context, mode *config.MtlsEnforcementMode,
) MTLSEnforcement {
	if mode == nil {
		return ""
	}
	switch *mode {
	case config.MtlsEnforcementMode_POLICY:
		return MTLSEnforcementPolicy
	case config.MtlsEnforcementMode_POLICY_WITH_DEFAULT_DENY:
		return MTLSEnforcementPolicyWithDefaultDeny
	case config.MtlsEnforcementMode_REJECT_CONNECTION:
		return MTLSEnforcementRejectConnection
	default:
		log.Error(ctx).Msgf("unknown mTLS enforcement mode %s", mode)
		return ""
	}
}
