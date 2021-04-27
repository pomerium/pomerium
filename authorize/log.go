package authorize

import (
	"context"
	"net/http"
	"strings"

	envoy_service_auth_v3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	"github.com/rs/zerolog"

	"github.com/pomerium/pomerium/authorize/evaluator"
	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/internal/telemetry/requestid"
	"github.com/pomerium/pomerium/internal/telemetry/trace"
	"github.com/pomerium/pomerium/pkg/grpc/audit"
	"github.com/pomerium/pomerium/pkg/grpc/user"
)

func (a *Authorize) logAuthorizeCheck(
	ctx context.Context,
	in *envoy_service_auth_v3.CheckRequest, out *envoy_service_auth_v3.CheckResponse,
	reply *evaluator.Result, u *user.User,
) {
	ctx, span := trace.StartSpan(ctx, "authorize.grpc.LogAuthorizeCheck")
	defer span.End()

	hdrs := getCheckRequestHeaders(in)
	hattrs := in.GetAttributes().GetRequest().GetHttp()
	evt := log.Info(ctx).Str("service", "authorize")
	// request
	evt = evt.Str("request-id", requestid.FromContext(ctx))
	evt = evt.Str("check-request-id", hdrs["X-Request-Id"])
	evt = evt.Str("method", hattrs.GetMethod())
	evt = evt.Str("path", stripQueryString(hattrs.GetPath()))
	evt = evt.Str("host", hattrs.GetHost())
	evt = evt.Str("query", hattrs.GetQuery())
	// reply
	if reply != nil {
		evt = evt.Bool("allow", reply.Status == http.StatusOK)
		evt = evt.Int("reply-status", reply.Status)
		evt = evt.Str("reply-message", reply.Message)
		evt = evt.Str("user", u.GetId())
		evt = evt.Str("email", u.GetEmail())
		evt = evt.Uint64("databroker_server_version", reply.DataBrokerServerVersion)
		evt = evt.Uint64("databroker_record_version", reply.DataBrokerRecordVersion)
	}

	// potentially sensitive, only log if debug mode
	if zerolog.GlobalLevel() <= zerolog.DebugLevel {
		evt = evt.Interface("headers", hdrs)
	}

	evt.Msg("authorize check")

	if enc := a.state.Load().auditEncryptor; enc != nil {
		ctx, span := trace.StartSpan(ctx, "authorize.grpc.AuditAuthorizeCheck")
		defer span.End()

		record := &audit.Record{
			Request:  in,
			Response: out,
		}
		if reply != nil {
			record.DatabrokerServerVersion = reply.DataBrokerServerVersion
			record.DatabrokerRecordVersion = reply.DataBrokerRecordVersion
		}
		sealed, err := enc.Encrypt(record)
		if err != nil {
			log.Warn(ctx).Err(err).Msg("authorize: error encrypting audit record")
			return
		}
		log.Info(ctx).
			Str("request-id", requestid.FromContext(ctx)).
			EmbedObject(sealed).
			Msg("audit log")
	}
}

func stripQueryString(str string) string {
	if idx := strings.Index(str, "?"); idx != -1 {
		str = str[:idx]
	}
	return str
}
