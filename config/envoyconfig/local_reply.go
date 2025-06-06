package envoyconfig

import (
	"encoding/json"
	"fmt"
	"slices"
	"strconv"
	"strings"

	envoy_config_accesslog_v3 "github.com/envoyproxy/go-control-plane/envoy/config/accesslog/v3"
	envoy_config_core_v3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	envoy_http_connection_manager "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
	"google.golang.org/grpc/codes"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/httputil"
	"github.com/pomerium/pomerium/ui"
)

// A ResponseFlag is an envoy response flag indicating errors.
type ResponseFlag struct {
	ShortName      string
	LongName       string
	Description    string
	GRPCStatusCode codes.Code
}

var responseFlags = []ResponseFlag{
	{"DC", "DownstreamConnectionTermination", "Downstream connection termination.", codes.Unavailable},
	{"DF", "DnsResolutionFailed", "The request was terminated due to DNS resolution failure.", codes.Unavailable},
	{"DI", "DelayInjected", "The request processing was delayed for a period specified via fault injection.", codes.Unavailable},
	{"DO", "DropOverload", "The request was terminated in addition to 503 response code due to drop_overloads.", codes.Unavailable},
	{"DPE", "DownstreamProtocolError", "The downstream request had an HTTP protocol error.", codes.Unknown},
	{"DT", "DurationTimeout", "When a request or connection exceeded max_connection_duration or max_downstream_connection_duration.", codes.DeadlineExceeded},
	{"FI", "FaultInjected", "The request was aborted with a response code specified via fault injection.", codes.Unavailable},
	{"IH", "InvalidEnvoyRequestHeaders", "The request was rejected because it set an invalid value for a strictly-checked header in addition to 400 response code.", codes.InvalidArgument},
	{"LH", "FailedLocalHealthCheck", "Local service failed health check request in addition to 503 response code.", codes.Unavailable},
	{"LR", "LocalReset", "Connection local reset in addition to 503 response code.", codes.Canceled},
	{"NC", "NoClusterFound", "Upstream cluster not found.", codes.Unavailable},
	{"NFCF", "NoFilterConfigFound", "The request is terminated because filter configuration was not received within the permitted warming deadline.", codes.Unavailable},
	{"NR", "NoRouteFound", "No route configured for a given request in addition to 404 response code or no matching filter chain for a downstream connection.", codes.NotFound},
	{"OM", "OverloadManagerTerminated", "Overload Manager terminated the request.", codes.Canceled},
	{"RFCF", "ResponseFromCacheFilter", "The response was served from an Envoy cache filter.", codes.Unknown},
	{"RL", "RateLimited", "The request was rate-limited locally by the HTTP rate limit filter in addition to 429 response code.", codes.ResourceExhausted},
	{"RLSE", "RateLimitServiceError", "The request was rejected because there was an error in rate limit service.", codes.Internal},
	{"SI", "StreamIdleTimeout", "Stream idle timeout in addition to 408 or 504 response code.", codes.DeadlineExceeded},
	// "UAEX" excluded because this response is handled in the authorize service
	{"UC", "UpstreamConnectionTermination", "Upstream connection termination in addition to 503 response code.", codes.Canceled},
	{"UF", "UpstreamConnectionFailure", "Upstream connection failure in addition to 503 response code.", codes.Unavailable},
	{"UH", "NoHealthyUpstream", "No healthy upstream hosts in upstream cluster in addition to 503 response code.", codes.Unavailable},
	{"UMSDR", "UpstreamMaxStreamDurationReached", "The upstream request reached max stream duration.", codes.DeadlineExceeded},
	{"UO", "UpstreamOverflow", "Upstream overflow (circuit breaking) in addition to 503 response code.", codes.Unavailable},
	{"UPE", "UpstreamProtocolError", "The upstream response had an HTTP protocol error.", codes.Internal},
	{"UR", "UpstreamRemoteReset", "Upstream remote reset in addition to 503 response code.", codes.Canceled},
	{"URX", "UpstreamRetryLimitExceeded", "The request was rejected because the upstream retry limit (HTTP) or maximum connect attempts (TCP) was reached.", codes.Unavailable},
	{"UT", "UpstreamRequestTimeout", "Upstream request timeout in addition to 504 response code.", codes.DeadlineExceeded},
}

// buildLocalReplyConfig builds the local reply config: the config used to modify "local" replies, that is replies
// coming directly from envoy
func (b *Builder) buildLocalReplyConfig(
	options *config.Options,
) (*envoy_http_connection_manager.LocalReplyConfig, error) {
	// add global headers for HSTS headers (#2110)
	var headers []*envoy_config_core_v3.HeaderValueOption
	// if we're the proxy or authenticate service, add our global headers
	if config.IsProxy(options.Services) || config.IsAuthenticate(options.Services) {
		headers = toEnvoyHeaders(options.GetSetResponseHeaders())
	}

	jsonBody, err := json.MarshalIndent(map[string]any{
		"requestId":  "%STREAM_ID%",
		"status":     "%RESPONSE_CODE%",
		"statusText": "%RESPONSE_CODE_DETAILS%",
	}, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("error rendering error json for local reply: %w", err)
	}

	data := make(map[string]any)
	httputil.AddBrandingOptionsToMap(data, options.BrandingOptions)
	for k, v := range data {
		// Escape any % signs in the branding options data, as Envoy will
		// interpret the page output as a substitution format string.
		if s, ok := v.(string); ok {
			data[k] = strings.ReplaceAll(s, "%", "%%")
		}
	}
	data["status"] = "%RESPONSE_CODE%"
	data["statusText"] = "%RESPONSE_CODE_DETAILS%"
	data["requestId"] = "%STREAM_ID%"
	data["responseFlags"] = "%RESPONSE_FLAGS%"

	htmlBody, err := ui.RenderPage("Error", "Error", data)
	if err != nil {
		return nil, fmt.Errorf("error rendering error page for local reply: %w", err)
	}

	responseFlagFilter := &envoy_config_accesslog_v3.AccessLogFilter_ResponseFlagFilter{
		ResponseFlagFilter: &envoy_config_accesslog_v3.ResponseFlagFilter{},
	}
	for _, rf := range responseFlags {
		responseFlagFilter.ResponseFlagFilter.Flags = append(responseFlagFilter.ResponseFlagFilter.Flags, rf.ShortName)
	}

	allMappers := []*envoy_http_connection_manager.ResponseMapper{
		{
			Filter: &envoy_config_accesslog_v3.AccessLogFilter{
				FilterSpecifier: &envoy_config_accesslog_v3.AccessLogFilter_AndFilter{
					AndFilter: &envoy_config_accesslog_v3.AndFilter{
						Filters: []*envoy_config_accesslog_v3.AccessLogFilter{
							{FilterSpecifier: responseFlagFilter},
							{FilterSpecifier: &envoy_config_accesslog_v3.AccessLogFilter_MetadataFilter{
								MetadataFilter: &envoy_config_accesslog_v3.MetadataFilter{
									Matcher: buildLocalReplyTypeMatcher("plain"),
								},
							}},
						},
					},
				},
			},
			BodyFormatOverride: &envoy_config_core_v3.SubstitutionFormatString{
				ContentType: "text/plain; charset=UTF-8",
				Format: &envoy_config_core_v3.SubstitutionFormatString_TextFormatSource{
					TextFormatSource: &envoy_config_core_v3.DataSource{
						Specifier: &envoy_config_core_v3.DataSource_InlineBytes{
							// just return the json body for plain text
							InlineBytes: jsonBody,
						},
					},
				},
			},
			HeadersToAdd: headers,
		},
		{
			Filter: &envoy_config_accesslog_v3.AccessLogFilter{
				FilterSpecifier: &envoy_config_accesslog_v3.AccessLogFilter_AndFilter{
					AndFilter: &envoy_config_accesslog_v3.AndFilter{
						Filters: []*envoy_config_accesslog_v3.AccessLogFilter{
							{FilterSpecifier: responseFlagFilter},
							{FilterSpecifier: &envoy_config_accesslog_v3.AccessLogFilter_MetadataFilter{
								MetadataFilter: &envoy_config_accesslog_v3.MetadataFilter{
									Matcher: buildLocalReplyTypeMatcher("json"),
								},
							}},
						},
					},
				},
			},
			BodyFormatOverride: &envoy_config_core_v3.SubstitutionFormatString{
				ContentType: "application/json; charset=UTF-8",
				Format: &envoy_config_core_v3.SubstitutionFormatString_TextFormatSource{
					TextFormatSource: &envoy_config_core_v3.DataSource{
						Specifier: &envoy_config_core_v3.DataSource_InlineBytes{
							InlineBytes: jsonBody,
						},
					},
				},
			},
			HeadersToAdd: headers,
		},
	}

	grpcMappers, err := b.buildLocalReplyMappersForGRPC(headers)
	if err != nil {
		return nil, err
	}
	allMappers = append(allMappers, grpcMappers...)

	// add the final fallback HTML error handler
	allMappers = append(allMappers, &envoy_http_connection_manager.ResponseMapper{
		Filter: &envoy_config_accesslog_v3.AccessLogFilter{
			FilterSpecifier: responseFlagFilter,
		},
		BodyFormatOverride: &envoy_config_core_v3.SubstitutionFormatString{
			ContentType: "text/html; charset=UTF-8",
			Format: &envoy_config_core_v3.SubstitutionFormatString_TextFormatSource{
				TextFormatSource: &envoy_config_core_v3.DataSource{
					Specifier: &envoy_config_core_v3.DataSource_InlineBytes{
						InlineBytes: htmlBody,
					},
				},
			},
		},
		HeadersToAdd: headers,
	})

	return &envoy_http_connection_manager.LocalReplyConfig{Mappers: allMappers}, nil
}

func (b *Builder) buildLocalReplyMappersForGRPC(
	headers []*envoy_config_core_v3.HeaderValueOption,
) ([]*envoy_http_connection_manager.ResponseMapper, error) {
	body, err := json.MarshalIndent(map[string]any{
		"requestId":  "%STREAM_ID%",
		"status":     "%RESPONSE_CODE%",
		"statusText": "%RESPONSE_CODE_DETAILS%",
	}, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("error rendering error json for local reply: %w", err)
	}

	var mappers []*envoy_http_connection_manager.ResponseMapper
	for _, responseFlag := range responseFlags {
		mappers = append(mappers, &envoy_http_connection_manager.ResponseMapper{
			Filter: &envoy_config_accesslog_v3.AccessLogFilter{
				FilterSpecifier: &envoy_config_accesslog_v3.AccessLogFilter_AndFilter{
					AndFilter: &envoy_config_accesslog_v3.AndFilter{
						Filters: []*envoy_config_accesslog_v3.AccessLogFilter{
							{FilterSpecifier: &envoy_config_accesslog_v3.AccessLogFilter_ResponseFlagFilter{
								ResponseFlagFilter: &envoy_config_accesslog_v3.ResponseFlagFilter{
									Flags: []string{responseFlag.ShortName},
								},
							}},
							{FilterSpecifier: &envoy_config_accesslog_v3.AccessLogFilter_MetadataFilter{
								MetadataFilter: &envoy_config_accesslog_v3.MetadataFilter{
									Matcher: buildLocalReplyTypeMatcher("grpc"),
								},
							}},
						},
					},
				},
			},
			BodyFormatOverride: &envoy_config_core_v3.SubstitutionFormatString{
				ContentType: "application/grpc+json; charset=UTF-8",
				Format: &envoy_config_core_v3.SubstitutionFormatString_TextFormatSource{
					TextFormatSource: &envoy_config_core_v3.DataSource{
						Specifier: &envoy_config_core_v3.DataSource_InlineBytes{
							InlineBytes: body,
						},
					},
				},
			},
			HeadersToAdd: slices.Concat(headers, []*envoy_config_core_v3.HeaderValueOption{
				{
					Header: &envoy_config_core_v3.HeaderValue{
						Key:   "grpc-status",
						Value: strconv.Itoa(int(responseFlag.GRPCStatusCode)),
					},
					AppendAction: envoy_config_core_v3.HeaderValueOption_ADD_IF_ABSENT,
				},
				{
					Header: &envoy_config_core_v3.HeaderValue{
						Key:   "grpc-message",
						Value: responseFlag.GRPCStatusCode.String(),
					},
					AppendAction: envoy_config_core_v3.HeaderValueOption_ADD_IF_ABSENT,
				},
			}),
		})
	}

	return mappers, nil
}
