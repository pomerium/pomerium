package config

import (
	"fmt"
	"strings"
	"time"

	envoy_extensions_clusters_common_dns_v3 "github.com/envoyproxy/go-control-plane/envoy/extensions/clusters/common/dns/v3"
	"github.com/volatiletech/null/v9"
)

// DNSOptions are options related to DNS.
type DNSOptions struct {
	// LookupFamily is the DNS IP address resolution policy.
	// If this setting is not specified, the value defaults to V4_PREFERRED.
	LookupFamily string `mapstructure:"dns_lookup_family" yaml:"dns_lookup_family,omitempty"`
	// UDPMaxqueries caps the number of UDP based DNS queries on a single port.
	UDPMaxQueries null.Uint32 `mapstructure:"dns_udp_max_queries" yaml:"dns_udp_max_queries,omitempty"`
	// UseTCP uses TCP for all DNS queries instead of the default protocol UDP.
	UseTCP null.Bool `mapstructure:"dns_use_tcp" yaml:"dns_use_tcp,omitempty"`
	// QueryTries is the maximum number of query attempts the resolver will make before giving up. Each attempt may use a different name server.
	QueryTries null.Uint32 `mapstructure:"dns_query_tries" yaml:"dns_query_tries,omitempty"`
	// QueryTimeout is the amount of time each name server is given to respond to a query on the first try of any given server.
	QueryTimeout time.Duration `mapstructure:"dns_query_timeout" yaml:"dns_query_timeout,omitempty"`
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

	return fmt.Errorf("unknown dns_lookup_family: %s, known families are: %s", value, strings.Join(AllDNSLookupFamilies, ", "))
}
