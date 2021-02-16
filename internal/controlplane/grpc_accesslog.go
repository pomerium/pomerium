package controlplane

import (
	"strings"

	envoy_service_accesslog_v2 "github.com/envoyproxy/go-control-plane/envoy/service/accesslog/v2"
	"github.com/golang/protobuf/ptypes"
	"github.com/rs/zerolog"

	"github.com/pomerium/pomerium/internal/log"
)

func (srv *Server) registerAccessLogHandlers() {
	envoy_service_accesslog_v2.RegisterAccessLogServiceServer(srv.GRPCServer, srv)
}

// StreamAccessLogs receives logs from envoy and prints them to stdout.
func (srv *Server) StreamAccessLogs(stream envoy_service_accesslog_v2.AccessLogService_StreamAccessLogsServer) error {
	for {
		msg, err := stream.Recv()
		if err != nil {
			log.Error().Err(err).Msg("access log stream error, disconnecting")
			return err
		}

		for _, entry := range msg.GetHttpLogs().LogEntry {
			reqPath := entry.GetRequest().GetPath()
			var evt *zerolog.Event
			if reqPath == "/ping" || reqPath == "/healthz" {
				evt = log.Debug()
			} else {
				evt = log.Info()
			}
			// common properties
			evt = evt.Str("service", "envoy")
			evt = evt.Str("upstream-cluster", entry.GetCommonProperties().GetUpstreamCluster())
			// request properties
			evt = evt.Str("method", entry.GetRequest().GetRequestMethod().String())
			evt = evt.Str("authority", entry.GetRequest().GetAuthority())
			evt = evt.Str("path", stripQueryString(reqPath))
			evt = evt.Str("user-agent", entry.GetRequest().GetUserAgent())
			evt = evt.Str("referer", stripQueryString(entry.GetRequest().GetReferer()))
			evt = evt.Str("forwarded-for", entry.GetRequest().GetForwardedFor())
			evt = evt.Str("request-id", entry.GetRequest().GetRequestId())
			// response properties
			dur, _ := ptypes.Duration(entry.CommonProperties.TimeToLastDownstreamTxByte)
			evt = evt.Dur("duration", dur)
			evt = evt.Uint64("size", entry.Response.ResponseBodyBytes)
			evt = evt.Uint32("response-code", entry.GetResponse().GetResponseCode().GetValue())
			evt = evt.Str("response-code-details", entry.GetResponse().GetResponseCodeDetails())
			evt.Msg("http-request")
		}
	}
}

func stripQueryString(str string) string {
	if idx := strings.Index(str, "?"); idx != -1 {
		str = str[:idx]
	}
	return str
}
