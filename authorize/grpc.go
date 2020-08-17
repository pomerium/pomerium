package authorize

import (
	"context"
	"errors"
	"io/ioutil"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"github.com/golang/protobuf/ptypes"
	"github.com/rs/zerolog"

	"github.com/pomerium/pomerium/authorize/evaluator"
	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/httputil"
	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/internal/sessions"
	"github.com/pomerium/pomerium/internal/telemetry/requestid"
	"github.com/pomerium/pomerium/internal/telemetry/trace"
	"github.com/pomerium/pomerium/internal/urlutil"
	"github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/grpc/session"
	"github.com/pomerium/pomerium/pkg/grpc/user"

	envoy_api_v2_core "github.com/envoyproxy/go-control-plane/envoy/api/v2/core"
	envoy_service_auth_v2 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v2"
)

var sessionTypeURL, userTypeURL string

func init() {
	any, _ := ptypes.MarshalAny(new(session.Session))
	sessionTypeURL = any.GetTypeUrl()

	any, _ = ptypes.MarshalAny(new(user.User))
	userTypeURL = any.GetTypeUrl()
}

// Check implements the envoy auth server gRPC endpoint.
func (a *Authorize) Check(ctx context.Context, in *envoy_service_auth_v2.CheckRequest) (*envoy_service_auth_v2.CheckResponse, error) {
	ctx, span := trace.StartSpan(ctx, "authorize.grpc.Check")
	defer span.End()

	state := a.state.Load()

	// maybe rewrite http request for forward auth
	isForwardAuth := a.handleForwardAuth(in)
	hreq := getHTTPRequestFromCheckRequest(in)
	rawJWT, _ := loadRawSession(hreq, a.currentOptions.Load(), state.encoder)
	sessionState, _ := loadSession(state.encoder, rawJWT)

	if err := a.forceSync(ctx, sessionState); err != nil {
		log.Warn().Err(err).Msg("clearing session due to force sync failed")
		sessionState = nil
	}

	a.dataBrokerDataLock.RLock()
	defer a.dataBrokerDataLock.RUnlock()

	req := a.getEvaluatorRequestFromCheckRequest(in, sessionState)
	reply, err := state.evaluator.Evaluate(ctx, req)
	if err != nil {
		log.Error().Err(err).Msg("error during OPA evaluation")
		return nil, err
	}
	logAuthorizeCheck(ctx, in, reply)

	switch {
	case reply.Status == http.StatusOK:
		return a.okResponse(reply), nil
	case reply.Status == http.StatusUnauthorized:
		if isForwardAuth {
			return a.deniedResponse(in, http.StatusUnauthorized, "Unauthenticated", nil), nil
		}
		return a.redirectResponse(in), nil
	}
	return a.deniedResponse(in, int32(reply.Status), reply.Message, nil), nil
}

func (a *Authorize) forceSync(ctx context.Context, ss *sessions.State) error {
	ctx, span := trace.StartSpan(ctx, "authorize.forceSync")
	defer span.End()
	if ss == nil {
		return nil
	}
	s := a.forceSyncSession(ctx, ss.ID)
	if s == nil {
		return errors.New("session not found")
	}
	a.forceSyncUser(ctx, s.GetUserId())
	return nil
}

func (a *Authorize) forceSyncSession(ctx context.Context, sessionID string) *session.Session {
	ctx, span := trace.StartSpan(ctx, "authorize.forceSyncSession")
	defer span.End()

	state := a.state.Load()

	a.dataBrokerDataLock.RLock()
	s, ok := a.dataBrokerData.Get(sessionTypeURL, sessionID).(*session.Session)
	a.dataBrokerDataLock.RUnlock()
	if ok {
		return s
	}

	res, err := state.dataBrokerClient.Get(ctx, &databroker.GetRequest{
		Type: sessionTypeURL,
		Id:   sessionID,
	})
	if err != nil {
		log.Warn().Err(err).Msg("failed to get session from databroker")
		return nil
	}

	a.dataBrokerDataLock.Lock()
	if current := a.dataBrokerData.Get(sessionTypeURL, sessionID); current == nil {
		a.dataBrokerData.Update(res.GetRecord())
	}
	s, _ = a.dataBrokerData.Get(sessionTypeURL, sessionID).(*session.Session)
	a.dataBrokerDataLock.Unlock()

	return s
}

func (a *Authorize) forceSyncUser(ctx context.Context, userID string) *user.User {
	ctx, span := trace.StartSpan(ctx, "authorize.forceSyncUser")
	defer span.End()

	state := a.state.Load()

	a.dataBrokerDataLock.RLock()
	u, ok := a.dataBrokerData.Get(userTypeURL, userID).(*user.User)
	a.dataBrokerDataLock.RUnlock()
	if ok {
		return u
	}

	res, err := state.dataBrokerClient.Get(ctx, &databroker.GetRequest{
		Type: userTypeURL,
		Id:   userID,
	})
	if err != nil {
		log.Warn().Err(err).Msg("failed to get user from databroker")
		return nil
	}

	a.dataBrokerDataLock.Lock()
	if current := a.dataBrokerData.Get(userTypeURL, userID); current == nil {
		a.dataBrokerData.Update(res.GetRecord())
	}
	u, _ = a.dataBrokerData.Get(userTypeURL, userID).(*user.User)
	a.dataBrokerDataLock.Unlock()

	return u
}

func (a *Authorize) getEnvoyRequestHeaders(signedJWT string) ([]*envoy_api_v2_core.HeaderValueOption, error) {
	var hvos []*envoy_api_v2_core.HeaderValueOption

	hdrs, err := a.getJWTClaimHeaders(a.currentOptions.Load(), signedJWT)
	if err != nil {
		return nil, err
	}
	for k, v := range hdrs {
		hvos = append(hvos, mkHeader(k, v, false))
	}

	return hvos, nil
}

func (a *Authorize) handleForwardAuth(req *envoy_service_auth_v2.CheckRequest) bool {
	opts := a.currentOptions.Load()

	if opts.ForwardAuthURL == nil {
		return false
	}

	checkURL := getCheckRequestURL(req)
	if urlutil.StripPort(checkURL.Host) != urlutil.StripPort(opts.GetForwardAuthURL().Host) {
		return false
	}

	uriQuery := checkURL.Query().Get("uri")
	if headers := req.GetAttributes().GetRequest().GetHttp().GetHeaders(); uriQuery == "" && headers != nil {
		uriQuery = headers[http.CanonicalHeaderKey(httputil.HeaderForwardedProto)] + "://" +
			headers[http.CanonicalHeaderKey(httputil.HeaderForwardedHost)]
		if xfu := headers[http.CanonicalHeaderKey(httputil.HeaderForwardedURI)]; xfu != "/" {
			uriQuery += xfu
		}
	}

	if (checkURL.Path != "/" && checkURL.Path != "/verify") || uriQuery == "" {
		return false
	}
	verifyURL, err := url.Parse(uriQuery)
	if err != nil {
		log.Warn().Str("uri", checkURL.Query().Get("uri")).Err(err).Msg("failed to parse uri for forward authentication")
		return false
	}

	req.Attributes.Request.Http.Scheme = verifyURL.Scheme
	req.Attributes.Request.Http.Host = verifyURL.Host
	req.Attributes.Request.Http.Path = verifyURL.Path

	// envoy sends the query string as part of the path
	if verifyURL.RawQuery != "" {
		req.Attributes.Request.Http.Path += "?" + verifyURL.RawQuery
	}
	return true
}

func (a *Authorize) getEvaluatorRequestFromCheckRequest(in *envoy_service_auth_v2.CheckRequest, sessionState *sessions.State) *evaluator.Request {
	requestURL := getCheckRequestURL(in)
	req := &evaluator.Request{
		DataBrokerData: a.dataBrokerData,
		HTTP: evaluator.RequestHTTP{
			Method:            in.GetAttributes().GetRequest().GetHttp().GetMethod(),
			URL:               requestURL.String(),
			Headers:           getCheckRequestHeaders(in),
			ClientCertificate: getPeerCertificate(in),
		},
	}
	if sessionState != nil {
		req.Session = evaluator.RequestSession{
			ID:                sessionState.ID,
			ImpersonateEmail:  sessionState.ImpersonateEmail,
			ImpersonateGroups: sessionState.ImpersonateGroups,
		}
	}
	p := a.getMatchingPolicy(requestURL)
	if p != nil {
		for _, sp := range p.SubPolicies {
			req.CustomPolicies = append(req.CustomPolicies, sp.Rego...)
		}
	}
	return req
}

func (a *Authorize) getMatchingPolicy(requestURL *url.URL) *config.Policy {
	options := a.currentOptions.Load()

	for _, p := range options.Policies {
		if p.Source == nil {
			continue
		}

		if p.Source.Host != requestURL.Host {
			continue
		}

		if p.Prefix != "" {
			if !strings.HasPrefix(requestURL.Path, p.Prefix) {
				continue
			}
		}

		if p.Path != "" {
			if requestURL.Path != p.Path {
				continue
			}
		}

		if p.Regex != "" {
			re, err := regexp.Compile(p.Regex)
			if err == nil && !re.MatchString(requestURL.String()) {
				continue
			}
		}

		return &p
	}

	return nil
}

func getHTTPRequestFromCheckRequest(req *envoy_service_auth_v2.CheckRequest) *http.Request {
	hattrs := req.GetAttributes().GetRequest().GetHttp()
	hreq := &http.Request{
		Method:     hattrs.GetMethod(),
		URL:        getCheckRequestURL(req),
		Header:     make(http.Header),
		Body:       ioutil.NopCloser(strings.NewReader(hattrs.GetBody())),
		Host:       hattrs.GetHost(),
		RequestURI: hattrs.GetPath(),
	}
	for k, v := range getCheckRequestHeaders(req) {
		hreq.Header.Set(k, v)
	}
	return hreq
}

func getCheckRequestHeaders(req *envoy_service_auth_v2.CheckRequest) map[string]string {
	hdrs := make(map[string]string)
	ch := req.GetAttributes().GetRequest().GetHttp().GetHeaders()
	for k, v := range ch {
		hdrs[http.CanonicalHeaderKey(k)] = v
	}
	return hdrs
}

func getCheckRequestURL(req *envoy_service_auth_v2.CheckRequest) *url.URL {
	h := req.GetAttributes().GetRequest().GetHttp()
	u := &url.URL{
		Scheme: h.GetScheme(),
		Host:   h.GetHost(),
	}
	u.Host = urlutil.GetDomainsForURL(u)[0]
	// envoy sends the query string as part of the path
	path := h.GetPath()
	if idx := strings.Index(path, "?"); idx != -1 {
		u.Path, u.RawQuery = path[:idx], path[idx+1:]
	} else {
		u.Path = path
	}

	if h.GetHeaders() != nil {
		if fwdProto, ok := h.GetHeaders()["x-forwarded-proto"]; ok {
			u.Scheme = fwdProto
		}
	}
	return u
}

// getPeerCertificate gets the PEM-encoded peer certificate from the check request
func getPeerCertificate(in *envoy_service_auth_v2.CheckRequest) string {
	// ignore the error as we will just return the empty string in that case
	cert, _ := url.QueryUnescape(in.GetAttributes().GetSource().GetCertificate())
	return cert
}

func logAuthorizeCheck(
	ctx context.Context,
	in *envoy_service_auth_v2.CheckRequest,
	reply *evaluator.Result,
) {
	hdrs := getCheckRequestHeaders(in)
	hattrs := in.GetAttributes().GetRequest().GetHttp()
	evt := log.Info().Str("service", "authorize")
	// request
	evt = evt.Str("request-id", requestid.FromContext(ctx))
	evt = evt.Str("check-request-id", hdrs["X-Request-Id"])
	evt = evt.Str("method", hattrs.GetMethod())
	evt = evt.Str("path", hattrs.GetPath())
	evt = evt.Str("host", hattrs.GetHost())
	evt = evt.Str("query", hattrs.GetQuery())
	// reply
	if reply != nil {
		evt = evt.Bool("allow", reply.Status == http.StatusOK)
		evt = evt.Int("status", reply.Status)
		evt = evt.Str("message", reply.Message)
	}

	// potentially sensitive, only log if debug mode
	if zerolog.GlobalLevel() <= zerolog.DebugLevel {
		evt = evt.Interface("headers", hdrs)
	}

	evt.Msg("authorize check")
}
