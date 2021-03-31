package config

import (
	"fmt"
	"net"
	"strconv"
	"strings"

	envoy_config_cluster_v3 "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
)

// DNSLookupFamily values.
const (
	DNSLookupFamilyAuto   = "AUTO"
	DNSLookupFamilyV4Only = "V4_ONLY"
	DNSLookupFamilyV6Only = "V6_ONLY"
)

// AllDNSLookupFamilies are all the available DNSLookupFamily values.
var AllDNSLookupFamilies = []string{DNSLookupFamilyV6Only, DNSLookupFamilyV4Only, DNSLookupFamilyAuto}

// ValidateDNSLookupFamily validates the value to confirm its one of the available DNS lookup families.
func ValidateDNSLookupFamily(value string) error {
	switch value {
	case "", DNSLookupFamilyAuto, DNSLookupFamilyV4Only, DNSLookupFamilyV6Only:
		return nil
	}

	return fmt.Errorf("unknown dns_lookup_family: %s, known families are: %s", value, strings.Join(AllDNSLookupFamilies, ", "))
}

// GetEnvoyDNSLookupFamily gets the envoy DNS lookup family.
func GetEnvoyDNSLookupFamily(value string) envoy_config_cluster_v3.Cluster_DnsLookupFamily {
	switch value {
	case DNSLookupFamilyV4Only:
		return envoy_config_cluster_v3.Cluster_V4_ONLY
	case DNSLookupFamilyV6Only:
		return envoy_config_cluster_v3.Cluster_V6_ONLY
	}
	return envoy_config_cluster_v3.Cluster_AUTO
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
