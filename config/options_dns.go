package config

import (
	"fmt"
	"strings"
	"time"

	envoy_extensions_clusters_common_dns_v3 "github.com/envoyproxy/go-control-plane/envoy/extensions/clusters/common/dns/v3"
	"github.com/volatiletech/null/v9"

	configpb "github.com/pomerium/pomerium/pkg/grpc/config"
)

// Errors
var (
	ErrDNSFailureRefreshRateTooShort = fmt.Errorf("config: dns_failure_refresh_rate must be at least 1ms")
	ErrDNSQueryTimeoutMustBePositive = fmt.Errorf("config: dns_query_timeout must be positive")
	ErrDNSRefreshRateTooShort        = fmt.Errorf("config: dns_refresh_rate must be at least 1ms")
	ErrUnknownDNSLookupFamily        = fmt.Errorf("config: unknown dns_lookup_family: known families are: %s", strings.Join(AllDNSLookupFamilies, ", "))
)

// DNSOptions are options related to DNS.
type DNSOptions struct {
	// FailureRefreshRate is the rate at which DNS lookups are refreshed when requests are failing.
	FailureRefreshRate *time.Duration `mapstructure:"dns_failure_refresh_rate" yaml:"dns_failure_refresh_rate,omitempty"`
	// LookupFamily is the DNS IP address resolution policy.
	// If this setting is not specified, the value defaults to V4_PREFERRED.
	LookupFamily string `mapstructure:"dns_lookup_family" yaml:"dns_lookup_family,omitempty"`
	// QueryTimeout is the amount of time each name server is given to respond to a query on the first try of any given server.
	QueryTimeout *time.Duration `mapstructure:"dns_query_timeout" yaml:"dns_query_timeout,omitempty"`
	// QueryTries is the maximum number of query attempts the resolver will make before giving up. Each attempt may use a different name server.
	QueryTries null.Uint32 `mapstructure:"dns_query_tries" yaml:"dns_query_tries,omitempty"`
	// RefreshRate is the rate at which DNS lookups are refreshed.
	RefreshRate *time.Duration `mapstructure:"dns_refresh_rate" yaml:"dns_refresh_rate,omitempty"`
	// UDPMaxqueries caps the number of UDP based DNS queries on a single port.
	UDPMaxQueries null.Uint32 `mapstructure:"dns_udp_max_queries" yaml:"dns_udp_max_queries,omitempty"`
	// UseTCP uses TCP for all DNS queries instead of the default protocol UDP.
	UseTCP null.Bool `mapstructure:"dns_use_tcp" yaml:"dns_use_tcp,omitempty"`
	// Resolves if provided, the DNS resolver to use. Each entry should be in form of an url, e.g. "udp://<ip>:<port>"
	Resolvers []string `mapstructure:"dns_resolvers" yaml:"dns_resolvers,omitempty"`
}

// FromProto sets options from a config settings protobuf.
func (o *DNSOptions) FromProto(src *configpb.Settings) {
	setOptionalDuration(&o.FailureRefreshRate, src.DnsFailureRefreshRate)
	set(&o.LookupFamily, src.DnsLookupFamily)
	setOptionalDuration(&o.QueryTimeout, src.DnsQueryTimeout)
	setNullableUint32(&o.QueryTries, src.DnsQueryTries)
	setOptionalDuration(&o.RefreshRate, src.DnsRefreshRate)
	setNullableUint32(&o.UDPMaxQueries, src.DnsUdpMaxQueries)
	setNullableBool(&o.UseTCP, src.DnsUseTcp)
}

// ToProto updates a config settings protobuf with dns options.
func (o *DNSOptions) ToProto(dst *configpb.Settings) {
	copyOptionalDuration(&dst.DnsFailureRefreshRate, o.FailureRefreshRate)
	copySrcToOptionalDest(&dst.DnsLookupFamily, &o.LookupFamily)
	copyOptionalDuration(&dst.DnsQueryTimeout, o.QueryTimeout)
	dst.DnsQueryTries = o.QueryTries.Ptr()
	dst.DnsUdpMaxQueries = o.UDPMaxQueries.Ptr()
	copyOptionalDuration(&dst.DnsRefreshRate, o.RefreshRate)
	dst.DnsUseTcp = o.UseTCP.Ptr()
}

// Validate validates the dns options.
func (o *DNSOptions) Validate() error {
	if err := ValidateDNSLookupFamily(o.LookupFamily); err != nil {
		return err
	}

	if o.FailureRefreshRate != nil && *o.FailureRefreshRate < time.Millisecond {
		return ErrDNSFailureRefreshRateTooShort
	}

	if o.QueryTimeout != nil && *o.QueryTimeout < 0 {
		return ErrDNSQueryTimeoutMustBePositive
	}

	if o.RefreshRate != nil && *o.RefreshRate < time.Millisecond {
		return ErrDNSRefreshRateTooShort
	}

	return nil
}

// DNSLookupFamily values.
const (
	DNSLookupFamilyAuto        = "AUTO"
	DNSLookupFamilyV4Only      = "V4_ONLY"
	DNSLookupFamilyV6Only      = "V6_ONLY"
	DNSLookupFamilyV4Preferred = "V4_PREFERRED"
	DNSLookupFamilyAll         = "ALL"
)

// AllDNSLookupFamilies are all the available DNSLookupFamily values.
var AllDNSLookupFamilies = []string{
	DNSLookupFamilyAuto,
	DNSLookupFamilyV4Only,
	DNSLookupFamilyV6Only,
	DNSLookupFamilyV4Preferred,
	DNSLookupFamilyAll,
}

// GetEnvoyDNSLookupFamily gets the envoy DNS lookup family.
func GetEnvoyDNSLookupFamily(value string) envoy_extensions_clusters_common_dns_v3.DnsLookupFamily {
	switch value {
	case DNSLookupFamilyAuto:
		return envoy_extensions_clusters_common_dns_v3.DnsLookupFamily_AUTO
	case DNSLookupFamilyV4Only:
		return envoy_extensions_clusters_common_dns_v3.DnsLookupFamily_V4_ONLY
	case DNSLookupFamilyV6Only:
		return envoy_extensions_clusters_common_dns_v3.DnsLookupFamily_V6_ONLY
	case DNSLookupFamilyV4Preferred:
		return envoy_extensions_clusters_common_dns_v3.DnsLookupFamily_V4_PREFERRED
	case DNSLookupFamilyAll:
		return envoy_extensions_clusters_common_dns_v3.DnsLookupFamily_ALL
	}

	// default
	return envoy_extensions_clusters_common_dns_v3.DnsLookupFamily_V4_PREFERRED
}

// ValidateDNSLookupFamily validates the value to confirm its one of the available DNS lookup families.
func ValidateDNSLookupFamily(value string) error {
	switch value {
	case "",
		DNSLookupFamilyAuto,
		DNSLookupFamilyV4Only,
		DNSLookupFamilyV6Only,
		DNSLookupFamilyV4Preferred,
		DNSLookupFamilyAll:
		return nil
	}

	return fmt.Errorf("%w: %s", ErrUnknownDNSLookupFamily, value)
}
