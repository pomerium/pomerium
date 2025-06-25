package config

import (
	"fmt"
	"net"
	"strconv"
	"strings"

	envoy_extensions_clusters_common_dns_v3 "github.com/envoyproxy/go-control-plane/envoy/extensions/clusters/common/dns/v3"
)

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

// ValidateCookieSameSite validates the cookie same site option.
func ValidateCookieSameSite(value string) error {
	value = strings.ToLower(value)
	switch value {
	case "", "strict", "lax", "none":
		return nil
	}
	return fmt.Errorf("unknown cookie_same_site: %s", value)
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

// ValidateMetricsAddress validates address for the metrics
func ValidateMetricsAddress(addr string) error {
	_, port, err := net.SplitHostPort(addr)
	if err != nil || port == "" {
		return fmt.Errorf("expected host:port")
	}

	p, err := strconv.Atoi(port)
	if err != nil {
		return fmt.Errorf("port must be a number")
	}
	if p <= 0 {
		return fmt.Errorf("expected positive port number")
	}

	return nil
}
