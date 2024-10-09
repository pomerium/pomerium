package config

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"regexp"

	envoy_tls "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/tls/v3"
	envoy_matcher "github.com/envoyproxy/go-control-plane/envoy/type/matcher/v3"

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

// SANType represents a certificate Subject Alternative Name type.
type SANType string

const (
	// SANTypeDNS represents a DNS name.
	SANTypeDNS SANType = "dns"

	// SANTypeEmail represents an email address.
	SANTypeEmail SANType = "email"

	// SANTypeIPAddress represents an IP address.
	SANTypeIPAddress SANType = "ip_address"

	// SANTypeURI represents a URI.
	SANTypeURI SANType = "uri"

	// SANTypeUserPrincipalName represents a UserPrincipalName (otherName with
	// type ID 1.3.6.1.4.1.311.20.2.3).
	SANTypeUserPrincipalName = "user_principal_name"
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

	// MatchSubjectAltNames is a list of SAN match expressions. When non-empty,
	// a client certificate must contain at least one Subject Alternative Name
	// that matches at least one of the expessions.
	MatchSubjectAltNames []SANMatcher `mapstructure:"match_subject_alt_names" yaml:"match_subject_alt_names,omitempty"`

	// MaxVerifyDepth is the maximum allowed depth of a certificate trust chain
	// (not counting the leaf certificate). The value 0 indicates no maximum.
	MaxVerifyDepth *uint32 `mapstructure:"max_verify_depth" yaml:"max_verify_depth,omitempty"`
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

// GetMaxVerifyDepth returns the maximum certificate chain depth. The value 0
// indicates no maximum.
func (s *DownstreamMTLSSettings) GetMaxVerifyDepth() uint32 {
	if s.MaxVerifyDepth == nil {
		return 1
	}
	return *s.MaxVerifyDepth
}

func (s *DownstreamMTLSSettings) validate() error {
	if s.CA != "" && s.CAFile != "" {
		return errors.New("cannot set both ca and ca_file")
	} else if _, err := s.GetCA(); err != nil {
		return err
	}

	if s.CRL != "" && s.CRLFile != "" {
		return errors.New("cannot set both crl and crl_file")
	}
	crl, err := s.GetCRL()
	if err != nil {
		return err
	} else if _, err := cryptutil.ParseCRLs(crl); err != nil {
		return fmt.Errorf("CRL: %w", err)
	}

	switch s.Enforcement {
	case "",
		MTLSEnforcementPolicy,
		MTLSEnforcementPolicyWithDefaultDeny,
		MTLSEnforcementRejectConnection: // OK
	default:
		return errors.New("unknown enforcement option")
	}

	for i := range s.MatchSubjectAltNames {
		if err := s.MatchSubjectAltNames[i].validate(); err != nil {
			return err
		}
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
	s.MatchSubjectAltNames = make([]SANMatcher, 0, len(p.MatchSubjectAltNames))
	for _, san := range p.MatchSubjectAltNames {
		var sanType SANType
		switch san.GetSanType() {
		case config.SANMatcher_DNS:
			sanType = SANTypeDNS
		case config.SANMatcher_EMAIL:
			sanType = SANTypeEmail
		case config.SANMatcher_IP_ADDRESS:
			sanType = SANTypeIPAddress
		case config.SANMatcher_URI:
			sanType = SANTypeURI
		case config.SANMatcher_USER_PRINCIPAL_NAME:
			sanType = SANTypeUserPrincipalName
		}
		s.MatchSubjectAltNames = append(s.MatchSubjectAltNames, SANMatcher{
			Type:    sanType,
			Pattern: san.GetPattern(),
		})
	}
	s.MaxVerifyDepth = p.MaxVerifyDepth
}

func (s *DownstreamMTLSSettings) ToProto() *config.DownstreamMtlsSettings {
	if s == nil {
		return nil
	}
	var settings config.DownstreamMtlsSettings
	var hasAnyFields bool
	if ca, err := s.GetCA(); err == nil && len(ca) > 0 {
		hasAnyFields = true
		caStr := base64.StdEncoding.EncodeToString(ca)
		settings.Ca = &caStr
	}
	if crl, err := s.GetCRL(); err == nil && len(crl) > 0 {
		hasAnyFields = true
		crlStr := base64.StdEncoding.EncodeToString(crl)
		settings.Crl = &crlStr
	}
	if s.Enforcement != "" {
		hasAnyFields = true
		switch s.Enforcement {
		case MTLSEnforcementPolicy:
			settings.Enforcement = config.MtlsEnforcementMode_POLICY.Enum()
		case MTLSEnforcementPolicyWithDefaultDeny:
			settings.Enforcement = config.MtlsEnforcementMode_POLICY_WITH_DEFAULT_DENY.Enum()
		case MTLSEnforcementRejectConnection:
			settings.Enforcement = config.MtlsEnforcementMode_REJECT_CONNECTION.Enum()
		default:
			settings.Enforcement = config.MtlsEnforcementMode_UNKNOWN.Enum()
		}
	}
	for _, san := range s.MatchSubjectAltNames {
		hasAnyFields = true
		var sanType config.SANMatcher_SANType
		switch san.Type {
		case SANTypeDNS:
			sanType = config.SANMatcher_DNS
		case SANTypeEmail:
			sanType = config.SANMatcher_EMAIL
		case SANTypeIPAddress:
			sanType = config.SANMatcher_IP_ADDRESS
		case SANTypeURI:
			sanType = config.SANMatcher_URI
		case SANTypeUserPrincipalName:
			sanType = config.SANMatcher_USER_PRINCIPAL_NAME
		default:
			sanType = config.SANMatcher_SAN_TYPE_UNSPECIFIED
		}
		settings.MatchSubjectAltNames = append(settings.MatchSubjectAltNames, &config.SANMatcher{
			SanType: sanType,
			Pattern: san.Pattern,
		})
	}
	settings.MaxVerifyDepth = s.MaxVerifyDepth
	hasAnyFields = hasAnyFields || s.MaxVerifyDepth != nil

	if !hasAnyFields {
		return nil
	}
	return &settings
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
		log.Ctx(ctx).Error().Msgf("unknown mTLS enforcement mode %s", mode)
		return ""
	}
}

// SANMatcher represents a Subject Alternative Name string matcher condition. A
// certificate satisfies this condition if it contains at least one SAN of the
// given type that matches the regular expression as a full string match.
type SANMatcher struct {
	Type    SANType
	Pattern string
}

func (s *SANMatcher) validate() error {
	if s.envoyType() == envoy_tls.SubjectAltNameMatcher_SAN_TYPE_UNSPECIFIED {
		return fmt.Errorf("unknown SAN type %q", s.Type)
	}
	if _, err := regexp.Compile(s.Pattern); err != nil {
		return fmt.Errorf("couldn't parse pattern %q: %w", s.Pattern, err)
	}
	return nil
}

// UnmarshalJSON implements the json.Unmarshaler interface.
func (s *SANMatcher) UnmarshalJSON(b []byte) error {
	var m map[string]string
	if err := json.Unmarshal(b, &m); err != nil {
		return err
	} else if len(m) != 1 {
		return errors.New("unsupported SAN matcher format: expected {type: pattern}")
	}

	for k, v := range m {
		s.Type = SANType(k)
		s.Pattern = v
	}
	return nil
}

// MarshalJSON implements the json.Marshaler interface.
func (s *SANMatcher) MarshalJSON() ([]byte, error) {
	return json.Marshal(map[string]string{string(s.Type): s.Pattern})
}

// ToEnvoyProto rerturns a representation of this matcher as an Envoy
// SubjectAltNameMatcher proto.
func (s *SANMatcher) ToEnvoyProto() *envoy_tls.SubjectAltNameMatcher {
	return &envoy_tls.SubjectAltNameMatcher{
		SanType: s.envoyType(),
		Matcher: &envoy_matcher.StringMatcher{
			MatchPattern: &envoy_matcher.StringMatcher_SafeRegex{
				SafeRegex: &envoy_matcher.RegexMatcher{
					EngineType: &envoy_matcher.RegexMatcher_GoogleRe2{},
					Regex:      s.Pattern,
				},
			},
		},
		Oid: s.oid(),
	}
}

func (s *SANMatcher) envoyType() envoy_tls.SubjectAltNameMatcher_SanType {
	switch s.Type {
	case SANTypeDNS:
		return envoy_tls.SubjectAltNameMatcher_DNS
	case SANTypeEmail:
		return envoy_tls.SubjectAltNameMatcher_EMAIL
	case SANTypeIPAddress:
		return envoy_tls.SubjectAltNameMatcher_IP_ADDRESS
	case SANTypeURI:
		return envoy_tls.SubjectAltNameMatcher_URI
	case SANTypeUserPrincipalName:
		return envoy_tls.SubjectAltNameMatcher_OTHER_NAME
	default:
		return envoy_tls.SubjectAltNameMatcher_SAN_TYPE_UNSPECIFIED
	}
}

func (s *SANMatcher) oid() string {
	switch s.Type {
	case SANTypeUserPrincipalName:
		return "1.3.6.1.4.1.311.20.2.3"
	default:
		return ""
	}
}
