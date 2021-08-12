package envoyconfig

import (
	"net/url"
	"regexp"
	"strings"

	envoy_type_matcher_v3 "github.com/envoyproxy/go-control-plane/envoy/type/matcher/v3"
)

func (b *Builder) buildSubjectAlternativeNameMatcher(
	dst *url.URL,
	overrideName string,
) *envoy_type_matcher_v3.StringMatcher {
	sni := dst.Hostname()
	if overrideName != "" {
		sni = overrideName
	}

	if strings.Contains(sni, "*") {
		pattern := regexp.QuoteMeta(sni)
		pattern = strings.Replace(pattern, "\\*", ".*", -1)
		return &envoy_type_matcher_v3.StringMatcher{
			MatchPattern: &envoy_type_matcher_v3.StringMatcher_SafeRegex{
				SafeRegex: &envoy_type_matcher_v3.RegexMatcher{
					EngineType: &envoy_type_matcher_v3.RegexMatcher_GoogleRe2{
						GoogleRe2: &envoy_type_matcher_v3.RegexMatcher_GoogleRE2{},
					},
					Regex: pattern,
				},
			},
		}
	}

	return &envoy_type_matcher_v3.StringMatcher{
		MatchPattern: &envoy_type_matcher_v3.StringMatcher_Exact{
			Exact: sni,
		},
	}
}

func (b *Builder) buildSubjectNameIndication(
	dst *url.URL,
	overrideName string,
) string {
	sni := dst.Hostname()
	if overrideName != "" {
		sni = overrideName
	}
	sni = strings.Replace(sni, "*", "example", -1)
	return sni
}
