package authorize

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	envoy_service_auth_v3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/pomerium/pomerium/authorize/checkrequest"
	"github.com/pomerium/pomerium/authorize/evaluator"
	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/config/envoyconfig"
	"github.com/pomerium/pomerium/internal/httputil"
	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/internal/mcp"
	"github.com/pomerium/pomerium/internal/sessions"
	"github.com/pomerium/pomerium/pkg/contextutil"
	"github.com/pomerium/pomerium/pkg/grpc/session"
	"github.com/pomerium/pomerium/pkg/grpc/user"
	"github.com/pomerium/pomerium/pkg/grpcutil"
	"github.com/pomerium/pomerium/pkg/policy/criteria"
	"github.com/pomerium/pomerium/pkg/storage"
	"github.com/pomerium/pomerium/pkg/telemetry/requestid"
)

// Check implements the envoy auth server gRPC endpoint.
func (a *Authorize) Check(ctx context.Context, in *envoy_service_auth_v3.CheckRequest) (*envoy_service_auth_v3.CheckResponse, error) {
	ctx, span := a.tracer.Start(ctx, "authorize.grpc.Check")
	defer span.End()

	ctx = a.withQuerierForCheckRequest(ctx)

	state := a.state.Load()

	// convert the incoming envoy-style http request into a go-style http request
	hreq := getHTTPRequestFromCheckRequest(in)
	requestID := requestid.FromHTTPHeader(hreq.Header)
	ctx = requestid.WithValue(ctx, requestID)

	req, err := a.getEvaluatorRequestFromCheckRequest(ctx, in)
	if err != nil {
		log.Ctx(ctx).Error().Err(err).Str("request-id", requestID).Msg("error building evaluator request")
		return nil, err
	}

	// load the session
	s, err := a.loadSession(ctx, hreq, req)
	if errors.Is(err, sessions.ErrInvalidSession) {
		// ENG-2172: if this is an invalid session, don't evaluate policy, return forbidden
		return a.deniedResponse(ctx, in, int32(http.StatusForbidden), http.StatusText(http.StatusForbidden), nil)
	} else if err != nil {
		return nil, fmt.Errorf("error loading session: %w", err)
	}

	// if there's a session or service account, load the user
	var u *user.User
	if s != nil {
		req.Session.ID = s.GetId()
		u, _ = a.getDataBrokerUser(ctx, s.GetUserId()) // ignore any missing user error
	}

	// For MCP routes that only require authentication (not full authorization),
	// if we have a valid session, allow the request without running policy evaluation
	// as policy for MCP may contain check for i.e. tool calls that are not relevant at this stage.
	if a.currentConfig.Load().Options.IsRuntimeFlagSet(config.RuntimeFlagMCP) {
		if req.Policy.IsMCPServer() && strings.HasPrefix(hreq.URL.Path, mcp.DefaultPrefix) {
			if s != nil {
				return a.requireLoginResponse(ctx, in, req)
			}
			a.logAuthorizeCheck(ctx, req, &evaluator.Result{
				Allow: evaluator.NewRuleResult(true, criteria.ReasonMCPHandshake),
			}, s, u)
			return a.okResponse(make(http.Header)), nil
		}
	}

	res, err := state.evaluator.Evaluate(ctx, req)
	if err != nil {
		log.Ctx(ctx).Error().Err(err).Str("request-id", requestID).Msg("error during OPA evaluation")
		return nil, err
	}

	// if show error details is enabled, attach the policy evaluation traces
	if req.Policy != nil && req.Policy.ShowErrorDetails {
		ctx = contextutil.WithPolicyEvaluationTraces(ctx, res.Traces)
	}

	resp, err := a.handleResult(ctx, in, req, res)
	if err != nil {
		log.Ctx(ctx).Error().Err(err).Str("request-id", requestID).Msg("grpc check ext_authz_error")
	}
	a.logAuthorizeCheck(ctx, req, res, s, u)
	return resp, err
}

func (a *Authorize) loadSession(
	ctx context.Context,
	hreq *http.Request,
	req *evaluator.Request,
) (s sessionOrServiceAccount, err error) {
	requestID := requestid.FromHTTPHeader(hreq.Header)

	s, err = a.maybeGetSessionFromRequest(ctx, hreq, req.Policy)
	if err == nil {
		return s, nil
	} else if !errors.Is(err, sessions.ErrNoSessionFound) {
		log.Ctx(ctx).Info().
			Str("request-id", requestID).
			Err(err).
			Msg("error creating session from incoming request")
		return nil, err
	}

	sessionState, _ := a.state.Load().sessionStore.LoadSessionStateAndCheckIDP(hreq)
	if sessionState == nil {
		return nil, nil
	}

	s, err = a.getDataBrokerSessionOrServiceAccount(ctx, sessionState.ID, sessionState.DatabrokerRecordVersion)
	if status.Code(err) == codes.Unavailable {
		log.Ctx(ctx).Debug().Str("request-id", requestID).Err(err).Msg("temporary error checking authorization: data broker unavailable")
		return nil, err
	} else if err != nil {
		log.Ctx(ctx).Info().Err(err).Str("request-id", requestID).Msg("clearing session due to missing or invalid session or service account")
		return nil, nil
	}

	return s, nil
}

func (a *Authorize) maybeGetSessionFromRequest(
	ctx context.Context,
	hreq *http.Request,
	policy *config.Policy,
) (*session.Session, error) {
	if a.currentConfig.Load().Options.IsRuntimeFlagSet(config.RuntimeFlagMCP) {
		if policy.IsMCPServer() || strings.HasPrefix(hreq.URL.Path, mcp.DefaultPrefix) {
			s, err := a.getMCPSession(ctx, hreq)
			if err != nil {
				log.Ctx(ctx).Error().Err(err).Msg("error getting mcp session")
				return nil, err
			}
			return s, nil
		}
	}

	// attempt to create a session from an incoming idp token
	return a.state.Load().idpTokenSessionCreator.
		CreateSession(ctx, a.currentConfig.Load(), policy, hreq)
}

func (a *Authorize) getMCPSession(
	ctx context.Context,
	hreq *http.Request,
) (*session.Session, error) {
	auth := hreq.Header.Get(httputil.HeaderAuthorization)
	if auth == "" {
		return nil, fmt.Errorf("no authorization header was provided: %w", sessions.ErrNoSessionFound)
	}

	prefix := "Bearer "
	if !strings.HasPrefix(strings.ToLower(auth), strings.ToLower(prefix)) {
		return nil, fmt.Errorf("authorization header does not start with %q: %w", prefix, sessions.ErrNoSessionFound)
	}

	accessToken := auth[len(prefix):]
	sessionID, err := a.state.Load().mcp.GetSessionIDFromAccessToken(accessToken)
	if err != nil {
		return nil, fmt.Errorf("no session found for access token: %w", sessions.ErrNoSessionFound)
	}

	record, err := storage.GetDataBrokerRecord(ctx, grpcutil.GetTypeURL(new(session.Session)), sessionID, 0)
	if storage.IsNotFound(err) {
		return nil, fmt.Errorf("session databroker record not found: %w", sessions.ErrNoSessionFound)
	}

	msg, err := record.GetData().UnmarshalNew()
	if err != nil {
		return nil, fmt.Errorf("error unmarshalling session: %w: %w", err, sessions.ErrNoSessionFound)
	}

	s, ok := msg.(*session.Session)
	if !ok {
		return nil, fmt.Errorf("unexpected session type: %T: %w", msg, sessions.ErrNoSessionFound)
	}

	return s, nil
}

func (a *Authorize) getEvaluatorRequestFromCheckRequest(
	ctx context.Context,
	in *envoy_service_auth_v3.CheckRequest,
) (*evaluator.Request, error) {
	attrs := in.GetAttributes()
	req := &evaluator.Request{
		IsInternal:         envoyconfig.ExtAuthzContextExtensionsIsInternal(attrs.GetContextExtensions()),
		HTTP:               evaluator.RequestHTTPFromCheckRequest(ctx, in),
		EnvoyRouteChecksum: envoyconfig.ExtAuthzContextExtensionsRouteChecksum(attrs.GetContextExtensions()),
		EnvoyRouteID:       envoyconfig.ExtAuthzContextExtensionsRouteID(attrs.GetContextExtensions()),
	}
	req.Policy = a.getMatchingPolicy(req.EnvoyRouteID)

	if req.Policy.IsMCPServer() {
		var ok bool
		req.MCP, ok = evaluator.RequestMCPFromCheckRequest(in)
		if !ok {
			log.Ctx(ctx).Error().
				Str("request-id", requestid.FromContext(ctx)).
				Str("route_id", req.EnvoyRouteID).
				Msg("failed to parse MCP request from check request")
		} else {
			log.Ctx(ctx).Debug().
				Str("request-id", requestid.FromContext(ctx)).
				Str("route_id", req.EnvoyRouteID).
				Str("mcp_tool", req.MCP.Tool).
				Str("mcp_method", req.MCP.Method).
				Msg("authorize request from check request")
		}
	}

	return req, nil
}

func (a *Authorize) getMatchingPolicy(routeID string) *config.Policy {
	options := a.currentConfig.Load().Options

	for p := range options.GetAllPolicies() {
		id, _ := p.RouteID()
		if id == routeID {
			return p
		}
	}

	return nil
}

func (a *Authorize) withQuerierForCheckRequest(ctx context.Context) context.Context {
	state := a.state.Load()
	q := storage.NewQuerier(state.dataBrokerClient)
	// if sync queriers are enabled, use those
	if len(state.syncQueriers) > 0 {
		m := map[string]storage.Querier{}
		for recordType, sq := range state.syncQueriers {
			m[recordType] = storage.NewFallbackQuerier(sq, q)
		}
		q = storage.NewTypedQuerier(q, m)
	}
	q = storage.NewCachingQuerier(q, storage.GlobalCache)
	return storage.WithQuerier(ctx, q)
}

func getHTTPRequestFromCheckRequest(req *envoy_service_auth_v3.CheckRequest) *http.Request {
	hattrs := req.GetAttributes().GetRequest().GetHttp()
	u := checkrequest.GetURL(req)
	hreq := &http.Request{
		Method:     hattrs.GetMethod(),
		URL:        &u,
		Header:     make(http.Header),
		Body:       io.NopCloser(strings.NewReader(hattrs.GetBody())),
		Host:       hattrs.GetHost(),
		RequestURI: hattrs.GetPath(),
	}
	for k, v := range getCheckRequestHeaders(req) {
		hreq.Header.Set(k, v)
	}
	return hreq
}

func getCheckRequestHeaders(req *envoy_service_auth_v3.CheckRequest) map[string]string {
	hdrs := make(map[string]string)
	ch := req.GetAttributes().GetRequest().GetHttp().GetHeaders()
	for k, v := range ch {
		hdrs[httputil.CanonicalHeaderKey(k)] = v
	}
	return hdrs
}
