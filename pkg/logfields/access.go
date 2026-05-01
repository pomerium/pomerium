package logfields

import (
	"errors"
	"fmt"

	"github.com/hashicorp/go-set/v3"
)

// An AccessLogField is a field in the access logs.
type AccessLogField string

// Cluster metadata constants for custom tags in access logs
const (
	// ClusterMetadataNamespace is the namespace used to store cluster metadata for access logs
	ClusterMetadataNamespace = "com.pomerium.cluster"
	// ClusterMetadataStatNameKey is the key used to store the cluster stat name in cluster metadata
	ClusterMetadataStatNameKey = "stat_name"
	// ClusterStatNameCustomTag is the custom tag name used to access cluster stat name in access logs
	ClusterStatNameCustomTag = "cluster_stat_name"
)

// known access log fields
const (
	AccessLogFieldAuthority           AccessLogField = "authority"
	AccessLogFieldClientCertificate   AccessLogField = "client-certificate"
	AccessLogFieldClusterStatName     AccessLogField = "cluster-stat-name"
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
)

func AllAccessLogFields() []AccessLogField {
	return []AccessLogField{
		AccessLogFieldAuthority,
		AccessLogFieldClientCertificate,
		AccessLogFieldClusterStatName,
		AccessLogFieldDuration,
		AccessLogFieldForwardedFor,
		AccessLogFieldIP,
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
	}
}

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

var accessLogFieldLookup = set.From(AllAccessLogFields())

// Validate returns an error if the access log field is invalid.
func (field AccessLogField) Validate() error {
	if _, ok := GetHeaderField(field); ok {
		return nil
	}

	if !accessLogFieldLookup.Contains(field) {
		return fmt.Errorf("%w: %s", ErrUnknownAccessLogField, field)
	}

	return nil
}
