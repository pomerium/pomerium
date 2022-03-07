package authorize

import (
	"context"
	"strings"

	envoy_service_auth_v3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	"github.com/rs/zerolog"

	"github.com/pomerium/pomerium/authorize/evaluator"
	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/internal/telemetry/requestid"
	"github.com/pomerium/pomerium/internal/telemetry/trace"
	"github.com/pomerium/pomerium/pkg/grpc/audit"
	"github.com/pomerium/pomerium/pkg/grpc/session"
	"github.com/pomerium/pomerium/pkg/grpc/user"
	"github.com/pomerium/pomerium/pkg/grpcutil"
)

func (a *Authorize) logAuthorizeCheck(
	ctx context.Context,
	in *envoy_service_auth_v3.CheckRequest, out *envoy_service_auth_v3.CheckResponse,
	res *evaluator.Result, s sessionOrServiceAccount, u *user.User,
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
	evt = evt.Str("ip", in.GetAttributes().GetSource().GetAddress().GetSocketAddress().GetAddress())

	// session information
	if s, ok := s.(*session.Session); ok {
		evt = a.populateLogSessionDetails(evt, s)
	}
	if sa, ok := s.(*user.ServiceAccount); ok {
		evt = evt.Str("service-account-id", sa.GetId())
	}

	// result
	if res != nil {
		evt = evt.Bool("allow", res.Allow.Value)
		if res.Allow.Value {
			evt = evt.Strs("allow-why-true", res.Allow.Reasons.Strings())
		} else {
			evt = evt.Strs("allow-why-false", res.Allow.Reasons.Strings())
		}
		evt = evt.Bool("deny", res.Deny.Value)
		if res.Deny.Value {
			evt = evt.Strs("deny-why-true", res.Deny.Reasons.Strings())
		} else {
			evt = evt.Strs("deny-why-false", res.Deny.Reasons.Strings())
		}
		evt = evt.Str("user", u.GetId())
		evt = evt.Str("email", u.GetEmail())
		evt = evt.Uint64("databroker_server_version", res.DataBrokerServerVersion)
		evt = evt.Uint64("databroker_record_version", res.DataBrokerRecordVersion)
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
		if res != nil {
			record.DatabrokerServerVersion = res.DataBrokerServerVersion
			record.DatabrokerRecordVersion = res.DataBrokerRecordVersion
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

func (a *Authorize) populateLogSessionDetails(evt *zerolog.Event, s *session.Session) *zerolog.Event {
	evt = evt.Str("session-id", s.GetId())
	if s.GetImpersonateSessionId() == "" {
		return evt
	}

	evt = evt.Str("impersonate-session-id", s.GetImpersonateSessionId())
	impersonatedSession, ok := a.store.GetRecordData(
		grpcutil.GetTypeURL(new(session.Session)),
		s.GetImpersonateSessionId(),
	).(*session.Session)
	if !ok {
		return evt
	}
	evt = evt.Str("impersonate-user-id", impersonatedSession.GetUserId())

	impersonatedUser, ok := a.store.GetRecordData(
		grpcutil.GetTypeURL(new(user.User)),
		impersonatedSession.GetUserId(),
	).(*user.User)
	if !ok {
		return evt
	}
	evt = evt.Str("impersonate-email", impersonatedUser.GetEmail())

	return evt
}

func stripQueryString(str string) string {
	if idx := strings.Index(str, "?"); idx != -1 {
		str = str[:idx]
	}
	return str
}
