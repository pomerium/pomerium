package envoyconfig

import envoy_type_matcher_v3 "github.com/envoyproxy/go-control-plane/envoy/type/matcher/v3"

func buildLocalReplyTypeMatcher(localReplyType string) *envoy_type_matcher_v3.MetadataMatcher {
	return &envoy_type_matcher_v3.MetadataMatcher{
		Filter: "envoy.filters.http.lua",
		Path: []*envoy_type_matcher_v3.MetadataMatcher_PathSegment{{
			Segment: &envoy_type_matcher_v3.MetadataMatcher_PathSegment_Key{
				Key: "pomerium_local_reply_type",
			},
		}},
		Value: &envoy_type_matcher_v3.ValueMatcher{
			MatchPattern: &envoy_type_matcher_v3.ValueMatcher_StringMatch{
				StringMatch: &envoy_type_matcher_v3.StringMatcher{
					MatchPattern: &envoy_type_matcher_v3.StringMatcher_Exact{
						Exact: localReplyType,
					},
				},
			},
		},
	}
}
