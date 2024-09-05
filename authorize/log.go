package authorize

import (
	"context"
	"strings"

	envoy_service_auth_v3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	"github.com/go-jose/go-jose/v3/jwt"
	"github.com/rs/zerolog"

	"github.com/pomerium/pomerium/authorize/evaluator"
	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/internal/telemetry/trace"
	"github.com/pomerium/pomerium/pkg/grpc/audit"
	"github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/grpc/session"
	"github.com/pomerium/pomerium/pkg/grpc/user"
	"github.com/pomerium/pomerium/pkg/grpcutil"
	"github.com/pomerium/pomerium/pkg/storage"
	"github.com/pomerium/pomerium/pkg/telemetry/requestid"
)

func (a *Authorize) logAuthorizeCheck(
	ctx context.Context,
	in *envoy_service_auth_v3.CheckRequest, out *envoy_service_auth_v3.CheckResponse,
	res *evaluator.Result, s sessionOrServiceAccount, u *user.User,
) {
	ctx, span := trace.StartSpan(ctx, "authorize.grpc.LogAuthorizeCheck")
	defer span.End()

	hdrs := getCheckRequestHeaders(in)
	impersonateDetails := a.getImpersonateDetails(ctx, s)

	evt := log.Info(ctx).Str("service", "authorize")
	fields := a.currentOptions.Load().GetAuthorizeLogFields()
	for _, field := range fields {
		evt = populateLogEvent(ctx, field, evt, in, s, u, hdrs, impersonateDetails)
	}
	evt = log.HTTPHeaders(evt, fields, hdrs)

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
	}

	evt.Msg("authorize check")

	if enc := a.state.Load().auditEncryptor; enc != nil {
		ctx, span := trace.StartSpan(ctx, "authorize.grpc.AuditAuthorizeCheck")
		defer span.End()

		record := &audit.Record{
			Request:  in,
			Response: out,
		}
		sealed, err := enc.Encrypt(record)
		if err != nil {
			log.Ctx(ctx).Error().Err(err).Msg("authorize: error encrypting audit record")
			return
		}
		log.Info(ctx).
			Str("request-id", requestid.FromContext(ctx)).
			EmbedObject(sealed).
			Msg("audit log")
	}
}

type impersonateDetails struct {
	email     string
	sessionID string
	userID    string
}

func (a *Authorize) getImpersonateDetails(
	ctx context.Context,
	s sessionOrServiceAccount,
) *impersonateDetails {
	var sessionID string
	if s, ok := s.(*session.Session); ok {
		sessionID = s.GetImpersonateSessionId()
	}
	if sessionID == "" {
		return nil
	}

	querier := storage.GetQuerier(ctx)

	req := &databroker.QueryRequest{
		Type:  grpcutil.GetTypeURL(new(session.Session)),
		Limit: 1,
	}
	req.SetFilterByID(sessionID)
	res, err := querier.Query(ctx, req)
	if err != nil || len(res.GetRecords()) == 0 {
		return nil
	}

	impersonatedSessionMsg, err := res.GetRecords()[0].GetData().UnmarshalNew()
	if err != nil {
		return nil
	}
	impersonatedSession, ok := impersonatedSessionMsg.(*session.Session)
	if !ok {
		return nil
	}
	userID := impersonatedSession.GetUserId()

	req = &databroker.QueryRequest{
		Type:  grpcutil.GetTypeURL(new(user.User)),
		Limit: 1,
	}
	req.SetFilterByID(userID)
	res, err = querier.Query(ctx, req)
	if err != nil || len(res.GetRecords()) == 0 {
		return nil
	}

	impersonatedUserMsg, err := res.GetRecords()[0].GetData().UnmarshalNew()
	if err != nil {
		return nil
	}
	impersonatedUser, ok := impersonatedUserMsg.(*user.User)
	if !ok {
		return nil
	}
	email := impersonatedUser.GetEmail()

	return &impersonateDetails{
		sessionID: sessionID,
		userID:    userID,
		email:     email,
	}
}

func populateLogEvent(
	ctx context.Context,
	field log.AuthorizeLogField,
	evt *zerolog.Event,
	in *envoy_service_auth_v3.CheckRequest,
	s sessionOrServiceAccount,
	u *user.User,
	hdrs map[string]string,
	impersonateDetails *impersonateDetails,
) *zerolog.Event {
	path, query, _ := strings.Cut(in.GetAttributes().GetRequest().GetHttp().GetPath(), "?")

	switch field {
	case log.AuthorizeLogFieldCheckRequestID:
		return evt.Str(string(field), hdrs["X-Request-Id"])
	case log.AuthorizeLogFieldEmail:
		return evt.Str(string(field), u.GetEmail())
	case log.AuthorizeLogFieldHost:
		return evt.Str(string(field), in.GetAttributes().GetRequest().GetHttp().GetHost())
	case log.AuthorizeLogFieldIDToken:
		if s, ok := s.(*session.Session); ok {
			evt = evt.Str(string(field), s.GetIdToken().GetRaw())
		}
		return evt
	case log.AuthorizeLogFieldIDTokenClaims:
		if s, ok := s.(*session.Session); ok {
			if t, err := jwt.ParseSigned(s.GetIdToken().GetRaw()); err == nil {
				var m map[string]any
				_ = t.UnsafeClaimsWithoutVerification(&m)
				evt = evt.Interface(string(field), m)
			}
		}
		return evt
	case log.AuthorizeLogFieldImpersonateEmail:
		if impersonateDetails != nil {
			evt = evt.Str(string(field), impersonateDetails.email)
		}
		return evt
	case log.AuthorizeLogFieldImpersonateSessionID:
		if impersonateDetails != nil {
			evt = evt.Str(string(field), impersonateDetails.sessionID)
		}
		return evt
	case log.AuthorizeLogFieldImpersonateUserID:
		if impersonateDetails != nil {
			evt = evt.Str(string(field), impersonateDetails.userID)
		}
		return evt
	case log.AuthorizeLogFieldIP:
		return evt.Str(string(field), in.GetAttributes().GetSource().GetAddress().GetSocketAddress().GetAddress())
	case log.AuthorizeLogFieldMethod:
		return evt.Str(string(field), in.GetAttributes().GetRequest().GetHttp().GetMethod())
	case log.AuthorizeLogFieldPath:
		return evt.Str(string(field), path)
	case log.AuthorizeLogFieldQuery:
		return evt.Str(string(field), query)
	case log.AuthorizeLogFieldRequestID:
		return evt.Str(string(field), requestid.FromContext(ctx))
	case log.AuthorizeLogFieldServiceAccountID:
		if sa, ok := s.(*user.ServiceAccount); ok {
			evt = evt.Str(string(field), sa.GetId())
		}
		return evt
	case log.AuthorizeLogFieldSessionID:
		if s, ok := s.(*session.Session); ok {
			evt = evt.Str(string(field), s.GetId())
		}
		return evt
	case log.AuthorizeLogFieldUser:
		var userID string
		if s != nil {
			userID = s.GetUserId()
		}
		return evt.Str(string(field), userID)
	default:
		return evt
	}
}
