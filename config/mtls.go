package config

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"regexp"
	"strings"

	envoy_tls "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/tls/v3"
	envoy_matcher "github.com/envoyproxy/go-control-plane/envoy/type/matcher/v3"

	"github.com/pomerium/pomerium/pkg/cryptutil"
	configpb "github.com/pomerium/pomerium/pkg/grpc/config"
	"github.com/pomerium/pomerium/pkg/nullable"
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
	Enforcement nullable.Value[configpb.MtlsEnforcementMode] `mapstructure:"enforcement" yaml:"enforcement,omitempty"`

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
func (s *DownstreamMTLSSettings) GetEnforcement() configpb.MtlsEnforcementMode {
	if !s.Enforcement.IsSet || s.Enforcement.Value == configpb.MtlsEnforcementMode_UNKNOWN {
		return configpb.MtlsEnforcementMode_POLICY_WITH_DEFAULT_DENY
	}
	return s.Enforcement.Value
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

	for i := range s.MatchSubjectAltNames {
		if err := s.MatchSubjectAltNames[i].validate(); err != nil {
			return err
		}
	}

	return nil
}

func (s *DownstreamMTLSSettings) applySettingsProto(
	_ context.Context, p *configpb.DownstreamMtlsSettings,
) {
	if p == nil {
		return
	}
	set(&s.CA, p.Ca)
	set(&s.CRL, p.Crl)
	s.Enforcement = nullable.FromPtr(p.Enforcement)
	s.MatchSubjectAltNames = make([]SANMatcher, 0, len(p.MatchSubjectAltNames))
	for _, san := range p.MatchSubjectAltNames {
		s.MatchSubjectAltNames = append(s.MatchSubjectAltNames, SANMatcher{
			Type:    nullable.From(san.SanType),
			Pattern: san.GetPattern(),
		})
	}
	s.MaxVerifyDepth = p.MaxVerifyDepth
}

func (s *DownstreamMTLSSettings) ToProto() *configpb.DownstreamMtlsSettings {
	if s == nil {
		return nil
	}
	var settings configpb.DownstreamMtlsSettings
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
	settings.Enforcement = s.Enforcement.Ptr()
	for _, san := range s.MatchSubjectAltNames {
		hasAnyFields = true
		settings.MatchSubjectAltNames = append(settings.MatchSubjectAltNames, &configpb.SANMatcher{
			SanType: san.Type.Value,
			Pattern: san.Pattern,
		})
	}
	settings.MaxVerifyDepth = s.MaxVerifyDepth
	hasAnyFields = hasAnyFields || s.MaxVerifyDepth != nil || settings.Enforcement != nil

	if !hasAnyFields {
		return nil
	}
	return &settings
}

// SANMatcher represents a Subject Alternative Name string matcher condition. A
// certificate satisfies this condition if it contains at least one SAN of the
// given type that matches the regular expression as a full string match.
type SANMatcher struct {
	Type    nullable.Value[configpb.SANMatcher_SANType]
	Pattern string
}

func (s *SANMatcher) validate() error {
	if s.envoyType() == envoy_tls.SubjectAltNameMatcher_SAN_TYPE_UNSPECIFIED {
		return fmt.Errorf("unknown SAN type %q", s.Type.Value)
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
		if e, ok := configpb.SANMatcher_SANType_value[strings.ToUpper(k)]; ok {
			s.Type = nullable.From(configpb.SANMatcher_SANType(e))
		}
		s.Pattern = v
	}
	return nil
}

// MarshalJSON implements the json.Marshaler interface.
func (s *SANMatcher) MarshalJSON() ([]byte, error) {
	return json.Marshal(map[string]string{strings.ToLower(s.Type.Value.String()): s.Pattern})
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
	switch s.Type.Value {
	case configpb.SANMatcher_DNS:
		return envoy_tls.SubjectAltNameMatcher_DNS
	case configpb.SANMatcher_EMAIL:
		return envoy_tls.SubjectAltNameMatcher_EMAIL
	case configpb.SANMatcher_IP_ADDRESS:
		return envoy_tls.SubjectAltNameMatcher_IP_ADDRESS
	case configpb.SANMatcher_URI:
		return envoy_tls.SubjectAltNameMatcher_URI
	case configpb.SANMatcher_USER_PRINCIPAL_NAME:
		return envoy_tls.SubjectAltNameMatcher_OTHER_NAME
	default:
		return envoy_tls.SubjectAltNameMatcher_SAN_TYPE_UNSPECIFIED
	}
}

func (s *SANMatcher) oid() string {
	switch s.Type.Value {
	case configpb.SANMatcher_USER_PRINCIPAL_NAME:
		return "1.3.6.1.4.1.311.20.2.3"
	default:
		return ""
	}
}
