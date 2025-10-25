package log

import (
	"errors"
	"fmt"
)

// An AccessLogField is a field in the access logs.
type AccessLogField string

// known access log fields
const (
	AccessLogFieldAuthority           AccessLogField = "authority"
	AccessLogFieldClusterStatsName    AccessLogField = "cluster-stats-name"
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
	AccessLogFieldClusterStatsName:    {},
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

// Validate returns an error if the access log field is invalid.
func (field AccessLogField) Validate() error {
	if _, ok := GetHeaderField(field); ok {
		return nil
	}

	_, ok := accessLogFieldLookup[field]
	if !ok {
		return fmt.Errorf("%w: %s", ErrUnknownAccessLogField, field)
	}

	return nil
}
