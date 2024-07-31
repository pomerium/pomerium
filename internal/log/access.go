package log

import (
	"errors"
	"fmt"
	"strings"

	envoy_data_accesslog_v3 "github.com/envoyproxy/go-control-plane/envoy/data/accesslog/v3"

	"github.com/pomerium/protoutil/paths"
)

// An AccessLogField is a field in the access logs.
type AccessLogField string

// known access log fields
const (
	AccessLogFieldAuthority           AccessLogField = "authority"
	AccessLogFieldDuration            AccessLogField = "duration"
	AccessLogFieldForwardedFor        AccessLogField = "forwarded-for"
	AccessLogFieldIP                  AccessLogField = "ip"
	AccessLogFieldMethod              AccessLogField = "method"
	AccessLogFieldPath                AccessLogField = "path"
	AccessLogFieldQuery               AccessLogField = "query"
	AccessLogFieldReferer             AccessLogField = "referer"
	AccessLogFieldRequestID           AccessLogField = "request-id"
	AccessLogFieldResponseCode        AccessLogField = "response-code"
	AccessLogFieldResponseCodeDetails AccessLogField = "response-code-details"
	AccessLogFieldSize                AccessLogField = "size"
	AccessLogFieldUpstreamCluster     AccessLogField = "upstream-cluster"
	AccessLogFieldUserAgent           AccessLogField = "user-agent"
	AccessLogFieldClientCertificate   AccessLogField = "client-certificate"
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

// DefaultAccessLogFields returns the default access log fields.
func DefaultAccessLogFields() []AccessLogField {
	return defaultAccessLogFields
}

// ErrUnknownAccessLogField indicates that an access log field is unknown.
var ErrUnknownAccessLogField = errors.New("unknown access log field")

var accessLogFieldLookup = map[AccessLogField]struct{}{
	AccessLogFieldAuthority:           {},
	AccessLogFieldDuration:            {},
	AccessLogFieldForwardedFor:        {},
	AccessLogFieldIP:                  {},
	AccessLogFieldMethod:              {},
	AccessLogFieldPath:                {},
	AccessLogFieldQuery:               {},
	AccessLogFieldReferer:             {},
	AccessLogFieldRequestID:           {},
	AccessLogFieldResponseCode:        {},
	AccessLogFieldResponseCodeDetails: {},
	AccessLogFieldSize:                {},
	AccessLogFieldUpstreamCluster:     {},
	AccessLogFieldUserAgent:           {},
	AccessLogFieldClientCertificate:   {},
}

var (
	httpAccessLogDesc = (*envoy_data_accesslog_v3.HTTPAccessLogEntry)(nil).ProtoReflect().Descriptor()
	tcpAccessLogDesc  = (*envoy_data_accesslog_v3.TCPAccessLogEntry)(nil).ProtoReflect().Descriptor()
)

// Validate returns an error if the access log field is invalid.
func (field AccessLogField) Validate() error {
	if _, ok := GetHeaderField(field); ok {
		return nil
	}

	if field.IsDynamicField() {
		pathStr := string(field[strings.IndexRune(string(field), '=')+1:])
		_, err := paths.ParseFrom(httpAccessLogDesc, pathStr)
		if err != nil {
			if errors.Is(err, paths.ErrFieldNotFound) {
				_, err2 := paths.ParseFrom(tcpAccessLogDesc, pathStr)
				if err2 == nil {
					return nil
				}
				err = errors.Join(err, err2)
			}
			return fmt.Errorf("invalid access log field '%s': %w", field, err)
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
