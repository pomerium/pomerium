package log

import (
	"errors"
	"fmt"
	"strings"

	envoy_data_accesslog_v3 "github.com/envoyproxy/go-control-plane/envoy/data/accesslog/v3"
	"github.com/pomerium/pomerium/pkg/protoutil/paths"
)

// An AccessLogField is a field in the access logs.
type AccessLogField string

// known access log fields
const (
	AccessLogFieldAuthority                        AccessLogField = "authority"
	AccessLogFieldDuration                         AccessLogField = "duration"
	AccessLogFieldForwardedFor                     AccessLogField = "forwarded-for"
	AccessLogFieldIP                               AccessLogField = "ip"
	AccessLogFieldDestIP                           AccessLogField = "dest-ip"
	AccessLogFieldDestPort                         AccessLogField = "dest-port"
	AccessLogFieldProtocolVersion                  AccessLogField = "protocol-version"
	AccessLogFieldMethod                           AccessLogField = "method"
	AccessLogFieldPath                             AccessLogField = "path"
	AccessLogFieldQuery                            AccessLogField = "query"
	AccessLogFieldReferer                          AccessLogField = "referer"
	AccessLogFieldRequestID                        AccessLogField = "request-id"
	AccessLogFieldResponseCode                     AccessLogField = "response-code"
	AccessLogFieldResponseCodeDetails              AccessLogField = "response-code-details"
	AccessLogFieldSize                             AccessLogField = "size"
	AccessLogFieldUpstreamCluster                  AccessLogField = "upstream-cluster"
	AccessLogFieldUserAgent                        AccessLogField = "user-agent"
	AccessLogFieldUpstreamTransportFailureReason   AccessLogField = "upstream-transport-failure-reason"
	AccessLogFieldDownstreamTransportFailureReason AccessLogField = "downstream-transport-failure-reason"
	AccessLogFieldTLSVersion                       AccessLogField = "tls-version"
	AccessLogFieldTLSSNIHostname                   AccessLogField = "tls-sni-hostname"
	AccessLogFieldTLSCipherSuite                   AccessLogField = "tls-cipher-suite"
	AccessLogFieldTLSLocalCert                     AccessLogField = "tls-local-cert"
	AccessLogFieldTLSPeerCert                      AccessLogField = "tls-peer-cert"
)

var defaultAccessLogFields = []AccessLogField{
	AccessLogFieldUpstreamCluster,
	AccessLogFieldMethod,
	AccessLogFieldAuthority,
	AccessLogFieldPath,
	AccessLogFieldUserAgent,
	AccessLogFieldReferer,
	AccessLogFieldForwardedFor,
	AccessLogFieldRequestID,
	AccessLogFieldDuration,
	AccessLogFieldSize,
	AccessLogFieldResponseCode,
	AccessLogFieldResponseCodeDetails,
}

var allAccessLogFields = []AccessLogField{
	AccessLogFieldAuthority,
	AccessLogFieldDuration,
	AccessLogFieldForwardedFor,
	AccessLogFieldIP,
	AccessLogFieldDestIP,
	AccessLogFieldDestPort,
	AccessLogFieldProtocolVersion,
	AccessLogFieldMethod,
	AccessLogFieldPath,
	AccessLogFieldQuery,
	AccessLogFieldReferer,
	AccessLogFieldRequestID,
	AccessLogFieldResponseCode,
	AccessLogFieldResponseCodeDetails,
	AccessLogFieldSize,
	AccessLogFieldUpstreamCluster,
	AccessLogFieldUserAgent,
	AccessLogFieldUpstreamTransportFailureReason,
	AccessLogFieldDownstreamTransportFailureReason,
	AccessLogFieldTLSVersion,
	AccessLogFieldTLSSNIHostname,
	AccessLogFieldTLSCipherSuite,
	AccessLogFieldTLSLocalCert,
	AccessLogFieldTLSPeerCert,
}

// DefaultAccessLogFields returns the default access log fields.
func DefaultAccessLogFields() []AccessLogField {
	return defaultAccessLogFields
}

// DefaultAccessLogFields returns the default access log fields.
func AllAccessLogFields() []AccessLogField {
	return allAccessLogFields
}

// ErrUnknownAccessLogField indicates that an access log field is unknown.
var ErrUnknownAccessLogField = errors.New("unknown access log field")

var accessLogFieldLookup = map[AccessLogField]struct{}{}

func init() {
	for _, field := range allAccessLogFields {
		accessLogFieldLookup[field] = struct{}{}
	}
}

var httpAccessLogDesc = (*envoy_data_accesslog_v3.HTTPAccessLogEntry)(nil).ProtoReflect().Descriptor()

// Validate returns an error if the access log field is invalid.
func (field AccessLogField) Validate() error {
	if _, ok := GetHeaderField(field); ok {
		return nil
	}

	if field.IsDynamicField() {
		_, err := paths.Parse(httpAccessLogDesc, string(field[strings.IndexRune(string(field), '=')+1:]))
		if err != nil {
			return fmt.Errorf("%w: %s", err, field)
		}
		return nil
	}

	_, ok := accessLogFieldLookup[field]
	if !ok {
		return fmt.Errorf("%w: %s", ErrUnknownAccessLogField, field)
	}

	return nil
}

func (field AccessLogField) IsWellKnownField() bool {
	_, ok := accessLogFieldLookup[field]
	return ok
}

func (field AccessLogField) IsDynamicField() bool {
	l, r, ok := strings.Cut(string(field), "=")
	return ok && len(l) > 0 && len(r) > 0 && r[0] == '.'
}
