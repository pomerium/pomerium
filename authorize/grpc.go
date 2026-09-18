package authorize

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	envoy_service_auth_v3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	"github.com/rs/zerolog"
	"go.opentelemetry.io/otel/attribute"
	oteltrace "go.opentelemetry.io/otel/trace"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/pomerium/pomerium/authorize/checkrequest"
	"github.com/pomerium/pomerium/authorize/evaluator"
	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/config/envoyconfig"
	"github.com/pomerium/pomerium/internal/agentic"
	"github.com/pomerium/pomerium/internal/httputil"
	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/internal/mcp"
	"github.com/pomerium/pomerium/internal/sessions"
	"github.com/pomerium/pomerium/pkg/contextutil"
	configpb "github.com/pomerium/pomerium/pkg/grpc/config"
	"github.com/pomerium/pomerium/pkg/grpc/session"
	"github.com/pomerium/pomerium/pkg/grpcutil"
	"github.com/pomerium/pomerium/pkg/storage"
	"github.com/pomerium/pomerium/pkg/telemetry/requestid"
)

// Check implements the envoy auth server gRPC endpoint.
func (a *Authorize) Check(ctx context.Context, in *envoy_service_auth_v3.CheckRequest) (*envoy_service_auth_v3.CheckResponse, error) {
	ctx, span := a.tracer.Start(ctx, "authorize.grpc.Check")
	defer span.End()

	ctx = a.withQuerierForCheckRequest(ctx)

	state := a.state.Load()
	mcpEnabled := a.currentConfig.Load().Options.IsRuntimeFlagSet(config.RuntimeFlagMCP)

	// convert the incoming envoy-style http request into a go-style http request
	hreq := getHTTPRequestFromCheckRequest(in)
	requestID := requestid.FromHTTPHeader(hreq.Header)
	ctx = requestid.WithValue(ctx, requestID)

	req, err := a.getEvaluatorRequestFromCheckRequest(ctx, in, mcpEnabled)
	if err != nil {
		log.Ctx(ctx).Error().Err(err).Str("request-id", requestID).Msg("error building evaluator request")
		return nil, err
	}

	// Add MCP information to trace if available
	if mcpEnabled {
		updateSpanWithMCPInfo(span, req.MCP)
	}

	// Handle CORS preflight for MCP server routes.
	// OPTIONS requests must be answered with CORS headers before any auth
	// checks because browsers send preflight requests without credentials.
	if mcpEnabled && req.Policy.IsMCPServer() &&
		in.GetAttributes().GetRequest().GetHttp().GetMethod() == http.MethodOptions {
		headers := make(http.Header)
		mcp.SetCORSHeaders(headers)
		return mkDeniedCheckResponse(http.StatusNoContent, headers, ""), nil
	}

	// Cookie + Authorization: Bearer are mutually exclusive trust contexts,
	// but only on the formats whose token is inherently machine-to-machine:
	// an external JWT or an agentic run token. Cookies come from a browser,
	// so a request carrying both is a misconfigured client or a confusion
	// attempt — reject with 400. The IdP access/identity token formats
	// predate this check and allow both credentials together (a logged-in
	// browser may send its IdP token via Authorization; see
	// TestBearerTokenFormat), and on pass-through routes the Authorization
	// header belongs to the upstream, so neither may be rejected here.
	cfg := a.currentConfig.Load()
	switch cfg.GetBearerTokenFormatForPolicy(req.Policy) {
	case configpb.BearerTokenFormat_BEARER_TOKEN_FORMAT_JWT,
		configpb.BearerTokenFormat_BEARER_TOKEN_FORMAT_AGENTIC_RUN_TOKEN:
		if hasCookieAndBearer(hreq, cfg.Options.CookieName) {
			log.Ctx(ctx).Info().
				Str("request-id", requestID).
				Msg("request carried both a session cookie and an Authorization: Bearer header on a machine-to-machine bearer-token route; rejecting as 400")
			return a.deniedResponse(ctx, in, int32(http.StatusBadRequest), http.StatusText(http.StatusBadRequest), nil)
		}
	}

	// load the session
	s, err := a.loadSession(ctx, hreq, req)
	if errors.Is(err, sessions.ErrInvalidSession) {
		// ENG-2172: if this is an invalid session, don't evaluate policy, return forbidden
		return a.deniedResponse(ctx, in, int32(http.StatusForbidden), http.StatusText(http.StatusForbidden), nil)
	} else if err != nil {
		return nil, fmt.Errorf("error loading session: %w", err)
	}

	if s != nil {
		req.Session.ID = s.GetId()
		req.Session.UserID = s.GetUserId()
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
	a.logAuthorizeCheck(ctx, zerolog.InfoLevel, req, res, s)
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

	h, hErr := a.state.Load().sessionStore.ReadSessionHandleAndCheckIDP(hreq)
	if h == nil {
		log.Ctx(ctx).Debug().
			Str("request-id", requestID).
			AnErr("handle-error", hErr).
			Msg("no session handle from request")
		return nil, nil
	}

	log.Ctx(ctx).Debug().
		Str("request-id", requestID).
		Str("handle-id", h.Id).
		Str("handle-idp-id", h.IdentityProviderId).
		Uint64("handle-record-version", h.GetDatabrokerRecordVersion()).
		Msg("decoded session handle from request")

	s, err = a.getDataBrokerSessionOrServiceAccount(ctx, h.Id, h.GetDatabrokerRecordVersion())
	if status.Code(err) == codes.Unavailable {
		log.Ctx(ctx).Debug().Str("request-id", requestID).Err(err).Msg("temporary error checking authorization: data broker unavailable")
		return nil, err
	} else if err != nil {
		log.Ctx(ctx).Info().Err(err).Str("request-id", requestID).Msg("clearing session due to missing or invalid session or service account")
		return nil, nil
	}

	return s, nil
}

// bearerResolution selects how maybeGetSessionFromRequest resolves an incoming
// request's Authorization: Bearer credential.
type bearerResolution int

const (
	// resolveNone leaves the credential to the idp-token creator, which may in
	// turn fall through to cookie handling.
	resolveNone bearerResolution = iota
	// resolveMCP resolves the bearer as an MCP access token.
	resolveMCP
	// resolveAgentic resolves the bearer as an opaque agentic run token.
	resolveAgentic
)

// resolveBearer decides — without side effects — which credential resolver a
// request should use. Run-token acceptance is declared per route, MCP routes
// included: a route interprets a run token only when it sets
// bearer_token_format: agentic_run_token. Normal MCP clients are unaffected,
// since an MCP access token carries no run-token prefix.
//
// Defense in depth rather than an absolute bound: GetBearerTokenFormatForPolicy
// falls back to the global bearer_token_format, so a deployment that sets
// agentic_run_token globally satisfies the check everywhere. What actually bounds
// the agent is that it reaches only the loopback listeners its sidecar serves,
// each pinned to a fixed upstream from an operator-authored template.
func resolveBearer(agenticEnabled, isMCPRoute, hasRunToken bool, format configpb.BearerTokenFormat) bearerResolution {
	switch {
	case agenticEnabled && hasRunToken &&
		format == configpb.BearerTokenFormat_BEARER_TOKEN_FORMAT_AGENTIC_RUN_TOKEN:
		return resolveAgentic
	case isMCPRoute:
		return resolveMCP
	default:
		return resolveNone
	}
}

func (a *Authorize) maybeGetSessionFromRequest(
	ctx context.Context,
	hreq *http.Request,
	policy *config.Policy,
) (*session.Session, error) {
	cfg := a.currentConfig.Load()
	opts := cfg.Options
	mcpEnabled := opts.IsRuntimeFlagSet(config.RuntimeFlagMCP)
	agenticEnabled := opts.IsRuntimeFlagSet(config.RuntimeFlagAgentic)
	isMCPRoute := mcpEnabled && (policy.IsMCPServer() || strings.HasPrefix(hreq.URL.Path, mcp.DefaultPrefix))

	runToken, hasRunToken := agentic.RunTokenFromAuthorizationHeader(hreq.Header.Get(httputil.HeaderAuthorization))

	switch resolveBearer(agenticEnabled, isMCPRoute, hasRunToken, cfg.GetBearerTokenFormatForPolicy(policy)) {
	case resolveAgentic:
		return a.getAgenticRunSession(ctx, runToken)
	case resolveMCP:
		s, err := a.getMCPSession(ctx, hreq)
		if err != nil {
			log.Ctx(ctx).Error().Err(err).Msg("error getting mcp session")
			return nil, err
		}
		return s, nil
	}

	// attempt to create a session from an incoming idp token
	return a.state.Load().idpTokenSessionCreator.
		CreateSession(ctx, cfg, policy, hreq)
}

// getAgenticRunSession resolves an opaque agentic run token to its session.
//
// Every *authentication* failure wraps sessions.ErrInvalidSession, which Check
// short-circuits to a 403 deny with no policy evaluation and no SSO redirect. It
// must never wrap sessions.ErrNoSessionFound here: that would fall through to
// cookie handling and redirect the run's M2M client into an interactive sign-in.
//
// Transient databroker errors (codes.Unavailable) are the exception: they are
// returned unwrapped so Check propagates a retryable error instead of denying a
// valid run token during a brief outage (mirrors loadSession).
func (a *Authorize) getAgenticRunSession(
	ctx context.Context,
	token string,
) (*session.Session, error) {
	state := a.state.Load()
	if state.agenticCipher == nil {
		return nil, fmt.Errorf("agentic: not configured: %w", sessions.ErrInvalidSession)
	}

	runID, sessionRecordVersion, err := agentic.ParseRunToken(state.agenticCipher, token)
	if err != nil {
		return nil, fmt.Errorf("agentic: invalid run token: %w: %w", err, sessions.ErrInvalidSession)
	}

	// Authoritative (uncached) read: revocation must take effect on the next
	// request. The querier cache used for the session read below keys its
	// invalidation off databroker server-version changes, so a revocation Put
	// from another client would not invalidate it promptly; the direct Get here
	// is what makes revocation immediate.
	run, err := agentic.GetRun(ctx, state.dataBrokerClient, runID)
	if status.Code(err) == codes.Unavailable {
		// Transient databroker outage: surface a retryable error rather than
		// wrapping ErrInvalidSession, which would permanently 403 a valid token.
		return nil, err
	} else if err != nil {
		return nil, fmt.Errorf("agentic: run not found: %w: %w", err, sessions.ErrInvalidSession)
	}
	switch {
	case run.GetRevoked():
		return nil, fmt.Errorf("agentic: run revoked: %w", sessions.ErrInvalidSession)
	case run.GetExpiresAt().AsTime().Before(time.Now()):
		return nil, fmt.Errorf("agentic: run expired: %w", sessions.ErrInvalidSession)
	case !agentic.IsApproved(run):
		// A token for an unapproved run cannot normally exist (Token refuses to mint
		// one), but keep the invariant local as defense in depth.
		return nil, fmt.Errorf("agentic: run not approved: %w", sessions.ErrInvalidSession)
	}

	// Cached, versioned session read — read-your-writes (same pattern as
	// getMCPSession), which also warms the cache entry the rego claim/ lookup uses.
	record, err := storage.GetDataBrokerRecord(ctx, grpcutil.GetTypeURL(new(session.Session)),
		agentic.SessionID(runID), sessionRecordVersion)
	if status.Code(err) == codes.Unavailable {
		return nil, err
	} else if err != nil {
		return nil, fmt.Errorf("agentic: session not found: %w: %w", err, sessions.ErrInvalidSession)
	}
	msg, err := record.GetData().UnmarshalNew()
	if err != nil {
		return nil, fmt.Errorf("agentic: bad session record: %w: %w", err, sessions.ErrInvalidSession)
	}
	s, ok := msg.(*session.Session)
	if !ok {
		return nil, fmt.Errorf("agentic: unexpected session type %T: %w", msg, sessions.ErrInvalidSession)
	}
	return s, nil
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
	sessionID, sessionRecordVersion, err := a.state.Load().mcp.GetSessionAndVersionFromAccessToken(accessToken)
	if err != nil {
		return nil, fmt.Errorf("no session found for access token: %w: %w", err, sessions.ErrNoSessionFound)
	}

	// Read the session with the record version captured when the token was
	// issued. This gives read-your-writes: if the synced-data cache is behind
	// that version (e.g. a session just written on another databroker node), the
	// querier falls through to an authoritative databroker read instead of
	// reporting the session as missing and denying with a 401.
	record, err := storage.GetDataBrokerRecord(ctx, grpcutil.GetTypeURL(new(session.Session)), sessionID, sessionRecordVersion)
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
	mcpEnabled bool,
) (*evaluator.Request, error) {
	attrs := in.GetAttributes()
	req := &evaluator.Request{
		IsInternal:         envoyconfig.ExtAuthzContextExtensionsIsInternal(attrs.GetContextExtensions()),
		HTTP:               evaluator.RequestHTTPFromCheckRequest(ctx, in),
		EnvoyRouteChecksum: envoyconfig.ExtAuthzContextExtensionsRouteChecksum(attrs.GetContextExtensions()),
		EnvoyRouteID:       envoyconfig.ExtAuthzContextExtensionsRouteID(attrs.GetContextExtensions()),
	}
	req.Policy = a.getMatchingPolicy(req.EnvoyRouteID)

	if mcpEnabled && req.Policy.IsMCPServer() {
		var err error
		req.MCP, err = evaluator.RequestMCPFromCheckRequest(in)
		if err != nil {
			log.Ctx(ctx).Error().
				Str("request-id", requestid.FromContext(ctx)).
				Err(err).
				Msg("error parsing MCP request from check request")
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
	q = storage.NewCachingQuerier(q, storage.GlobalCache)
	// if sync queriers are enabled, use those
	if len(state.syncQueriers) > 0 {
		m := map[string]storage.Querier{}
		for recordType, sq := range state.syncQueriers {
			m[recordType] = storage.NewFallbackQuerier(sq, q)
		}
		q = storage.NewTypedQuerier(q, m)
	}
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

func updateSpanWithMCPInfo(span oteltrace.Span, mcp evaluator.RequestMCP) {
	if mcp.Method == "" {
		return
	}
	span.SetAttributes(attribute.String("mcp.method", mcp.Method))
	if tc := mcp.ToolCall; tc != nil {
		span.SetAttributes(attribute.String("mcp.tool", tc.Name))
	}
}

// hasCookieAndBearer reports whether the request carries BOTH a Pomerium
// session cookie AND an Authorization: Bearer header. The two are mutually
// exclusive trust contexts (browser vs M2M).
func hasCookieAndBearer(r *http.Request, cookieName string) bool {
	if cookieName == "" {
		return false
	}
	// Check the (cheap) Authorization header before parsing cookies: the
	// common authenticated browser case carries a cookie but no bearer, so
	// short-circuiting here skips cookie parsing on the hot path.
	const prefix = "Bearer "
	auth := r.Header.Get(httputil.HeaderAuthorization)
	if len(auth) < len(prefix) || !strings.EqualFold(auth[:len(prefix)], prefix) {
		return false
	}
	_, err := r.Cookie(cookieName)
	return err == nil
}
