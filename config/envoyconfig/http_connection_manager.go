package envoyconfig

import (
	"strings"

	envoy_config_core_v3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	envoy_config_route_v3 "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	envoy_http_connection_manager "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
	"google.golang.org/protobuf/types/known/wrapperspb"

	"github.com/pomerium/pomerium/config"
)

func (b *Builder) buildVirtualHost(
	options *config.Options,
	name string,
	host string,
) (*envoy_config_route_v3.VirtualHost, error) {
	vh := &envoy_config_route_v3.VirtualHost{
		Name:    name,
		Domains: []string{host},
	}

	// if we're stripping the port from incoming requests
	// and this host doesn't have a port or wildcard in it
	// then we will add :* to match on any port
	if options.IsRuntimeFlagSet(config.RuntimeFlagMatchAnyIncomingPort) &&
		!strings.Contains(host, "*") &&
		!config.HasPort(host) {
		vh.Domains = append(vh.Domains, host+":*")
	}

	// these routes match /.pomerium/... and similar paths
	rs, err := b.buildPomeriumHTTPRoutes(options, host)
	if err != nil {
		return nil, err
	}
	vh.Routes = append(vh.Routes, rs...)

	return vh, nil
}

func (b *Builder) applyGlobalHTTPConnectionManagerOptions(hcm *envoy_http_connection_manager.HttpConnectionManager) {
	if hcm.InternalAddressConfig == nil {
		ranges := []*envoy_config_core_v3.CidrRange{
			// localhost
			{AddressPrefix: "127.0.0.1", PrefixLen: wrapperspb.UInt32(32)},

			// RFC1918
			{AddressPrefix: "10.0.0.0", PrefixLen: wrapperspb.UInt32(8)},
			{AddressPrefix: "192.168.0.0", PrefixLen: wrapperspb.UInt32(16)},
			{AddressPrefix: "172.16.0.0", PrefixLen: wrapperspb.UInt32(12)},
		}
		if b.addIPV6InternalRanges {
			ranges = append(ranges, []*envoy_config_core_v3.CidrRange{
				// Localhost IPv6
				{AddressPrefix: "::1", PrefixLen: wrapperspb.UInt32(128)},
				// RFC4193
				{AddressPrefix: "fd00::", PrefixLen: wrapperspb.UInt32(8)},
			}...)
		}

		// see doc comment on InternalAddressConfig for details
		hcm.InternalAddressConfig = &envoy_http_connection_manager.HttpConnectionManager_InternalAddressConfig{
			CidrRanges: ranges,
		}
	}
}
