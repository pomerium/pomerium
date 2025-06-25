package authorize

import (
	"context"
	"time"

	"github.com/go-jose/go-jose/v3/jwt"
	"github.com/rs/zerolog"
	"go.opentelemetry.io/otel/attribute"

	"github.com/pomerium/pomerium/authorize/evaluator"
	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/grpc/session"
	"github.com/pomerium/pomerium/pkg/grpc/user"
	"github.com/pomerium/pomerium/pkg/grpcutil"
	"github.com/pomerium/pomerium/pkg/storage"
	"github.com/pomerium/pomerium/pkg/telemetry/requestid"
)

func (a *Authorize) logAuthorizeCheck(
	ctx context.Context,
	req *evaluator.Request,
	res *evaluator.Result, s sessionOrServiceAccount, u *user.User,
) {
	ctx, span := a.tracer.Start(ctx, "authorize.grpc.LogAuthorizeCheck")
	defer span.End()

	start := time.Now()

	hdrs := req.HTTP.Headers
	impersonateDetails := a.getImpersonateDetails(ctx, s)

	evt := log.Ctx(ctx).Info().Str("service", "authorize")
	fields := a.currentConfig.Load().Options.GetAuthorizeLogFields()
	for _, field := range fields {
		evt = populateLogEvent(ctx, field, evt, req, s, u, impersonateDetails, res)
	}
	evt = log.HTTPHeaders(evt, fields, hdrs)

	// result
	if res != nil {
		span.SetAttributes(attribute.Bool("result.allow", res.Allow.Value))
		evt = evt.Bool("allow", res.Allow.Value)
		allowReasons := res.Allow.Reasons.Strings()
		if res.Allow.Value {
			span.SetAttributes(attribute.StringSlice("result.allow-why-true", allowReasons))
			evt = evt.Strs("allow-why-true", allowReasons)
		} else {
			span.SetAttributes(attribute.StringSlice("result.allow-why-false", allowReasons))
			evt = evt.Strs("allow-why-false", allowReasons)
		}
		evt = evt.Bool("deny", res.Deny.Value)
		denyReasons := res.Deny.Reasons.Strings()
		if res.Deny.Value {
			span.SetAttributes(attribute.StringSlice("result.deny-why-true", denyReasons))
			evt = evt.Strs("deny-why-true", denyReasons)
		} else {
			span.SetAttributes(attribute.StringSlice("result.deny-why-false", denyReasons))
			evt = evt.Strs("deny-why-false", denyReasons)
		}
	}

	evt.Msg("authorize check")
	a.logDuration.Record(ctx, time.Since(start).Milliseconds())
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
	req *evaluator.Request,
	s sessionOrServiceAccount,
	u *user.User,
	impersonateDetails *impersonateDetails,
	res *evaluator.Result,
) *zerolog.Event {
	switch field {
	case log.AuthorizeLogFieldCheckRequestID:
		return evt.Str(string(field), req.HTTP.Headers["X-Request-Id"])
	case log.AuthorizeLogFieldEmail:
		return evt.Str(string(field), u.GetEmail())
	case log.AuthorizeLogFieldEnvoyRouteChecksum:
		return evt.Uint64(string(field), req.EnvoyRouteChecksum)
	case log.AuthorizeLogFieldEnvoyRouteID:
		return evt.Str(string(field), req.EnvoyRouteID)
	case log.AuthorizeLogFieldHost:
		return evt.Str(string(field), req.HTTP.Host)
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
		return evt.Str(string(field), req.HTTP.IP)
	case log.AuthorizeLogFieldMCPMethod:
		return evt.Str(string(field), req.MCP.Method)
	case log.AuthorizeLogFieldMCPTool:
		if req.MCP.ToolCall != nil {
			return evt.Str(string(field), req.MCP.ToolCall.Name)
		}
		return evt
	case log.AuthorizeLogFieldMCPToolParameters:
		if req.MCP.ToolCall != nil && req.MCP.ToolCall.Arguments != nil {
			return evt.Interface(string(field), req.MCP.ToolCall.Arguments)
		}
		return evt
	case log.AuthorizeLogFieldMethod:
		return evt.Str(string(field), req.HTTP.Method)
	case log.AuthorizeLogFieldPath:
		return evt.Str(string(field), req.HTTP.RawPath)
	case log.AuthorizeLogFieldQuery:
		return evt.Str(string(field), req.HTTP.RawQuery)
	case log.AuthorizeLogFieldRequestID:
		return evt.Str(string(field), requestid.FromContext(ctx))
	case log.AuthorizeLogFieldRouteChecksum:
		if req.Policy != nil {
			return evt.Uint64(string(field), req.Policy.Checksum())
		}
		return evt
	case log.AuthorizeLogFieldRouteID:
		if req.Policy != nil {
			return evt.Str(string(field), req.Policy.ID)
		}
		return evt
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
		if res != nil {
			if v, ok := res.AdditionalLogFields[field]; ok {
				evt = evt.Interface(string(field), v)
			}
		}
		return evt
	}
}
