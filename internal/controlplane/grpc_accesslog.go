package controlplane

import (
	envoy_service_accesslog_v2 "github.com/envoyproxy/go-control-plane/envoy/service/accesslog/v2"
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
			evt := log.Info().Str("service", "envoy")
			// common properties
			evt = evt.Str("upstream-cluster", entry.GetCommonProperties().GetUpstreamCluster())
			// request properties
			evt = evt.Str("method", entry.GetRequest().GetRequestMethod().String())
			evt = evt.Str("authority", entry.GetRequest().GetAuthority())
			evt = evt.Str("path", entry.GetRequest().GetPath())
			evt = evt.Str("user-agent", entry.GetRequest().GetUserAgent())
			evt = evt.Str("referer", entry.GetRequest().GetReferer())
			evt = evt.Str("forwarded-for", entry.GetRequest().GetForwardedFor())
			evt = evt.Str("request-id", entry.GetRequest().GetRequestId())
			// response properties
			evt = evt.Uint32("response-code", entry.GetResponse().GetResponseCode().GetValue())
			evt = evt.Str("response-code-details", entry.GetResponse().GetResponseCodeDetails())
			evt.Msg("http-request")
		}
	}
}
