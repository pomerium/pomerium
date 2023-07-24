package controlplane

import (
	"net/http"
	"strings"

	envoy_data_accesslog_v3 "github.com/envoyproxy/go-control-plane/envoy/data/accesslog/v3"
	envoy_service_accesslog_v3 "github.com/envoyproxy/go-control-plane/envoy/service/accesslog/v3"
	"github.com/rs/zerolog"

	"github.com/pomerium/pomerium/internal/log"
)

func (srv *Server) registerAccessLogHandlers() {
	envoy_service_accesslog_v3.RegisterAccessLogServiceServer(srv.GRPCServer, srv)
}

// StreamAccessLogs receives logs from envoy and prints them to stdout.
func (srv *Server) StreamAccessLogs(stream envoy_service_accesslog_v3.AccessLogService_StreamAccessLogsServer) error {
	for {
		msg, err := stream.Recv()
		if err != nil {
			log.Error(stream.Context()).Err(err).Msg("access log stream error, disconnecting")
			return err
		}

		for _, entry := range msg.GetHttpLogs().LogEntry {
			requestHeaders := getRequestHeaders(entry)
			reqPath := entry.GetRequest().GetPath()
			var evt *zerolog.Event
			if reqPath == "/ping" || reqPath == "/healthz" {
				evt = log.Debug(stream.Context())
			} else {
				evt = log.Info(stream.Context())
			}
			evt = evt.Str("service", "envoy")
			for _, field := range srv.currentConfig.Load().Config.Options.GetAccessLogFields() {
				evt = populateLogEvent(field, evt, entry, requestHeaders)
			}
			evt.Msg("http-request")
		}
	}
}

func populateLogEvent(
	field log.AccessLogField,
	evt *zerolog.Event,
	entry *envoy_data_accesslog_v3.HTTPAccessLogEntry,
	requestHeaders map[string]string,
) *zerolog.Event {
	if headerName, ok := field.IsForHeader(); ok {
		return evt.Str("header."+headerName, requestHeaders[http.CanonicalHeaderKey(headerName)])
	}

	switch field {
	case log.AccessLogFieldAuthority:
		return evt.Str(string(field), entry.GetRequest().GetAuthority())
	case log.AccessLogFieldDuration:
		dur := entry.CommonProperties.TimeToLastDownstreamTxByte.AsDuration()
		return evt.Dur(string(field), dur)
	case log.AccessLogFieldForwardedFor:
		return evt.Str(string(field), entry.GetRequest().GetForwardedFor())
	case log.AccessLogFieldMethod:
		return evt.Str(string(field), entry.GetRequest().GetRequestMethod().String())
	case log.AccessLogFieldPath:
		return evt.Str(string(field), stripQueryString(entry.GetRequest().GetPath()))
	case log.AccessLogFieldReferer:
		return evt.Str(string(field), stripQueryString(entry.GetRequest().GetReferer()))
	case log.AccessLogFieldRequestID:
		return evt.Str(string(field), entry.GetRequest().GetRequestId())
	case log.AccessLogFieldResponseCode:
		return evt.Uint32(string(field), entry.GetResponse().GetResponseCode().GetValue())
	case log.AccessLogFieldResponseCodeDetails:
		return evt.Str(string(field), entry.GetResponse().GetResponseCodeDetails())
	case log.AccessLogFieldSize:
		return evt.Uint64(string(field), entry.Response.ResponseBodyBytes)
	case log.AccessLogFieldUpstreamCluster:
		return evt.Str(string(field), entry.GetCommonProperties().GetUpstreamCluster())
	case log.AccessLogFieldUserAgent:
		return evt.Str(string(field), entry.GetRequest().GetUserAgent())
	default:
		return evt
	}
}

func getRequestHeaders(entry *envoy_data_accesslog_v3.HTTPAccessLogEntry) map[string]string {
	m := map[string]string{}
	for k, v := range entry.GetRequest().GetRequestHeaders() {
		m[http.CanonicalHeaderKey(k)] = v
	}
	return m
}

func stripQueryString(str string) string {
	if idx := strings.Index(str, "?"); idx != -1 {
		str = str[:idx]
	}
	return str
}
