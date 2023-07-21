package log

// An AccessLogField is a field in the access logs.
type AccessLogField string

// known access log fields
const (
	AccessLogFieldAuthority           AccessLogField = "authority"
	AccessLogFieldDuration            AccessLogField = "duration"
	AccessLogFieldForwardedFor        AccessLogField = "forwarded-for"
	AccessLogFieldMethod              AccessLogField = "method"
	AccessLogFieldPath                AccessLogField = "path"
	AccessLogFieldReferer             AccessLogField = "referer"
	AccessLogFieldRequestID           AccessLogField = "request-id"
	AccessLogFieldResponseCode        AccessLogField = "response-code"
	AccessLogFieldResponseCodeDetails AccessLogField = "response-code-details"
	AccessLogFieldSize                AccessLogField = "size"
	AccessLogFieldUpstreamCluster     AccessLogField = "upstream-cluster"
	AccessLogFieldUserAgent           AccessLogField = "user-agent"
)

// DefaultAccessLogFields are the default access log fields to log.
var DefaultAccessLogFields = []AccessLogField{
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
