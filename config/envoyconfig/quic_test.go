package envoyconfig

import (
	"testing"

	envoy_config_common_mutation_rules_v3 "github.com/envoyproxy/go-control-plane/envoy/config/common/mutation_rules/v3"
	envoy_config_core_v3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	envoy_extensions_filters_http_header_mutation_v3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/header_mutation/v3"
	"github.com/volatiletech/null/v9"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/testutil"
)

func Test_newQUICAltSvcHeaderFilter(t *testing.T) {
	t.Parallel()

	testutil.AssertProtoEqual(t,
		HTTPHeaderMutationsFilter(&envoy_extensions_filters_http_header_mutation_v3.HeaderMutation{
			Mutations: &envoy_extensions_filters_http_header_mutation_v3.Mutations{
				ResponseMutations: []*envoy_config_common_mutation_rules_v3.HeaderMutation{{
					Action: &envoy_config_common_mutation_rules_v3.HeaderMutation_Append{
						Append: &envoy_config_core_v3.HeaderValueOption{
							Header: &envoy_config_core_v3.HeaderValue{
								Key:   "alt-svc",
								Value: `h3=":443"; ma=86400`,
							},
						},
					},
				}},
			},
		}),
		newQUICAltSvcHeaderFilter(&config.Config{
			Options: &config.Options{
				Addr: ":443",
			},
		}))
	testutil.AssertProtoEqual(t,
		HTTPHeaderMutationsFilter(&envoy_extensions_filters_http_header_mutation_v3.HeaderMutation{
			Mutations: &envoy_extensions_filters_http_header_mutation_v3.Mutations{
				ResponseMutations: []*envoy_config_common_mutation_rules_v3.HeaderMutation{{
					Action: &envoy_config_common_mutation_rules_v3.HeaderMutation_Append{
						Append: &envoy_config_core_v3.HeaderValueOption{
							Header: &envoy_config_core_v3.HeaderValue{
								Key:   "alt-svc",
								Value: `h3=":443"; ma=86400`,
							},
						},
					},
				}},
			},
		}),
		newQUICAltSvcHeaderFilter(&config.Config{
			Options: &config.Options{
				Addr:               ":8443",
				HTTP3AdvertisePort: null.Uint32From(443),
			},
		}))
}
