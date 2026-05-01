package controlplane

import (
	"bytes"
	"strings"
	"testing"
	"time"

	envoy_config_core_v3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	envoy_data_accesslog_v3 "github.com/envoyproxy/go-control-plane/envoy/data/accesslog/v3"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/wrapperspb"

	"github.com/pomerium/pomerium/pkg/logfields"
)

func Test_populateLogEvent(t *testing.T) {
	t.Parallel()

	entry := &envoy_data_accesslog_v3.HTTPAccessLogEntry{
		CommonProperties: &envoy_data_accesslog_v3.AccessLogCommon{
			DownstreamRemoteAddress: &envoy_config_core_v3.Address{
				Address: &envoy_config_core_v3.Address_SocketAddress{
					SocketAddress: &envoy_config_core_v3.SocketAddress{
						Address: "127.0.0.1",
					},
				},
			},
			TimeToLastDownstreamTxByte: durationpb.New(time.Second * 3),
			UpstreamCluster:            "UPSTREAM-CLUSTER",
		},
		Request: &envoy_data_accesslog_v3.HTTPRequestProperties{
			Authority:     "AUTHORITY",
			ForwardedFor:  "FORWARDED-FOR",
			Path:          "https://www.example.com/some/path?a=b",
			Referer:       "https://www.example.com/referer?a=b",
			RequestId:     "REQUEST-ID",
			RequestMethod: envoy_config_core_v3.RequestMethod_GET,
			UserAgent:     "USER-AGENT",
		},
		Response: &envoy_data_accesslog_v3.HTTPResponseProperties{
			ResponseBodyBytes:   1234,
			ResponseCode:        wrapperspb.UInt32(200),
			ResponseCodeDetails: "RESPONSE-CODE-DETAILS",
		},
	}

	var unknownAccessLogField logfields.AccessLogField = "blah"

	for _, tc := range []struct {
		field  logfields.AccessLogField
		entry  *envoy_data_accesslog_v3.HTTPAccessLogEntry
		expect string
	}{
		{logfields.AccessLogFieldAuthority, entry, `{"authority":"AUTHORITY"}`},
		{logfields.AccessLogFieldDuration, entry, `{"duration":3000}`},
		{logfields.AccessLogFieldForwardedFor, entry, `{"forwarded-for":"FORWARDED-FOR"}`},
		{logfields.AccessLogFieldIP, entry, `{"ip":"127.0.0.1"}`},
		{logfields.AccessLogFieldMethod, entry, `{"method":"GET"}`},
		{logfields.AccessLogFieldPath, entry, `{"path":"https://www.example.com/some/path"}`},
		{logfields.AccessLogFieldQuery, entry, `{"query":"a=b"}`},
		{logfields.AccessLogFieldReferer, entry, `{"referer":"https://www.example.com/referer"}`},
		{logfields.AccessLogFieldRequestID, entry, `{"request-id":"REQUEST-ID"}`},
		{logfields.AccessLogFieldResponseCode, entry, `{"response-code":200}`},
		{logfields.AccessLogFieldResponseCodeDetails, entry, `{"response-code-details":"RESPONSE-CODE-DETAILS"}`},
		{logfields.AccessLogFieldSize, entry, `{"size":1234}`},
		{logfields.AccessLogFieldUpstreamCluster, entry, `{"upstream-cluster":"UPSTREAM-CLUSTER"}`},
		{logfields.AccessLogFieldUserAgent, entry, `{"user-agent":"USER-AGENT"}`},
		{unknownAccessLogField, entry, "{}"}, // Unknown log fields should not cause errors
	} {
		t.Run(string(tc.field), func(t *testing.T) {
			t.Parallel()

			var buf bytes.Buffer
			log := zerolog.New(&buf)
			evt := log.Log()
			evt = populateLogEvent(tc.field, evt, tc.entry)
			evt.Send()

			assert.Equal(t, tc.expect, strings.TrimSpace(buf.String()))
		})
	}
}
