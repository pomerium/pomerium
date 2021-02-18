package authorize

import (
	"context"
	"encoding/base64"
	"errors"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"

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
	"github.com/pomerium/pomerium/pkg/grpcutil"

	envoy_service_auth_v2 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v2"
)

// Check implements the envoy auth server gRPC endpoint.
func (a *Authorize) Check(ctx context.Context, in *envoy_service_auth_v2.CheckRequest) (*envoy_service_auth_v2.CheckResponse, error) {
	ctx, span := trace.StartSpan(ctx, "authorize.grpc.Check")
	defer span.End()

	state := a.state.Load()

	// convert the incoming envoy-style http request into a go-style http request
	hreq := getHTTPRequestFromCheckRequest(in)

	isForwardAuth := a.isForwardAuth(in)
	if isForwardAuth {
		// update the incoming http request's uri to match the forwarded URI
		fwdAuthURI := getForwardAuthURL(hreq)
		in.Attributes.Request.Http.Scheme = fwdAuthURI.Scheme
		in.Attributes.Request.Http.Host = fwdAuthURI.Host
		in.Attributes.Request.Http.Path = fwdAuthURI.EscapedPath()
		if fwdAuthURI.RawQuery != "" {
			in.Attributes.Request.Http.Path += "?" + fwdAuthURI.RawQuery
		}
	}

	rawJWT, _ := loadRawSession(hreq, a.currentOptions.Load(), state.encoder)
	sessionState, _ := loadSession(state.encoder, rawJWT)

	u, err := a.forceSync(ctx, sessionState)
	if err != nil {
		log.Warn().Err(err).Msg("clearing session due to force sync failed")
		sessionState = nil
	}

	req, err := a.getEvaluatorRequestFromCheckRequest(in, sessionState)
	if err != nil {
		log.Warn().Err(err).Msg("error building evaluator request")
		return nil, err
	}

	reply, err := state.evaluator.Evaluate(ctx, req)
	if err != nil {
		log.Error().Err(err).Msg("error during OPA evaluation")
		return nil, err
	}
	logAuthorizeCheck(ctx, in, reply, u)

	switch {
	case reply.Status == http.StatusOK:
		return a.okResponse(reply), nil
	case reply.Status == http.StatusUnauthorized:
		if isForwardAuth && hreq.URL.Path == "/verify" {
			return a.deniedResponse(in, http.StatusUnauthorized, "Unauthenticated", nil)
		}
		return a.redirectResponse(in)
	}
	return a.deniedResponse(in, int32(reply.Status), reply.Message, nil)
}

func (a *Authorize) forceSync(ctx context.Context, ss *sessions.State) (*user.User, error) {
	ctx, span := trace.StartSpan(ctx, "authorize.forceSync")
	defer span.End()
	if ss == nil {
		return nil, nil
	}
	s := a.forceSyncSession(ctx, ss.ID)
	if s == nil {
		return nil, errors.New("session not found")
	}
	u := a.forceSyncUser(ctx, s.GetUserId())
	return u, nil
}

func (a *Authorize) forceSyncSession(ctx context.Context, sessionID string) interface{ GetUserId() string } {
	ctx, span := trace.StartSpan(ctx, "authorize.forceSyncSession")
	defer span.End()

	state := a.state.Load()

	s, ok := a.store.GetRecordData(grpcutil.GetTypeURL(new(session.Session)), sessionID).(*session.Session)
	if ok {
		return s
	}

	sa, ok := a.store.GetRecordData(grpcutil.GetTypeURL(new(user.ServiceAccount)), sessionID).(*user.ServiceAccount)
	if ok {
		return sa
	}

	res, err := state.dataBrokerClient.Get(ctx, &databroker.GetRequest{
		Type: grpcutil.GetTypeURL(new(session.Session)),
		Id:   sessionID,
	})
	if err != nil {
		log.Warn().Err(err).Msg("failed to get session from databroker")
		return nil
	}

	if current := a.store.GetRecordData(grpcutil.GetTypeURL(new(session.Session)), sessionID); current == nil {
		a.store.UpdateRecord(res.GetRecord())
	}
	s, _ = a.store.GetRecordData(grpcutil.GetTypeURL(new(session.Session)), sessionID).(*session.Session)

	return s
}

func (a *Authorize) forceSyncUser(ctx context.Context, userID string) *user.User {
	ctx, span := trace.StartSpan(ctx, "authorize.forceSyncUser")
	defer span.End()

	state := a.state.Load()

	u, ok := a.store.GetRecordData(grpcutil.GetTypeURL(new(user.User)), userID).(*user.User)
	if ok {
		return u
	}

	res, err := state.dataBrokerClient.Get(ctx, &databroker.GetRequest{
		Type: grpcutil.GetTypeURL(new(user.User)),
		Id:   userID,
	})
	if err != nil {
		log.Warn().Err(err).Msg("failed to get user from databroker")
		return nil
	}

	if current := a.store.GetRecordData(grpcutil.GetTypeURL(new(user.User)), userID); current == nil {
		a.store.UpdateRecord(res.GetRecord())
	}
	u, _ = a.store.GetRecordData(grpcutil.GetTypeURL(new(user.User)), userID).(*user.User)

	return u
}

func getForwardAuthURL(r *http.Request) *url.URL {
	urqQuery := r.URL.Query().Get("uri")
	u, _ := urlutil.ParseAndValidateURL(urqQuery)
	if u == nil {
		u = &url.URL{
			Scheme: r.Header.Get(httputil.HeaderForwardedProto),
			Host:   r.Header.Get(httputil.HeaderForwardedHost),
			Path:   r.Header.Get(httputil.HeaderForwardedURI),
		}
	}
	originalURL := r.Header.Get(httputil.HeaderOriginalURL)
	if originalURL != "" {
		k, _ := urlutil.ParseAndValidateURL(originalURL)
		if k != nil {
			u = k
		}
	}
	return u
}

// isForwardAuth returns if the current request is a forward auth route.
func (a *Authorize) isForwardAuth(req *envoy_service_auth_v2.CheckRequest) bool {
	opts := a.currentOptions.Load()

	if opts.ForwardAuthURL == nil {
		return false
	}

	forwardAuthURL, err := opts.GetForwardAuthURL()
	if err != nil {
		return false
	}

	checkURL := getCheckRequestURL(req)

	return urlutil.StripPort(checkURL.Host) == urlutil.StripPort(forwardAuthURL.Host)
}

func (a *Authorize) getEvaluatorRequestFromCheckRequest(
	in *envoy_service_auth_v2.CheckRequest,
	sessionState *sessions.State,
) (*evaluator.Request, error) {
	requestURL := getCheckRequestURL(in)
	req := &evaluator.Request{
		HTTP: evaluator.RequestHTTP{
			Method:            in.GetAttributes().GetRequest().GetHttp().GetMethod(),
			URL:               requestURL.String(),
			Headers:           getCheckRequestHeaders(in),
			ClientCertificate: getPeerCertificate(in),
		},
	}
	if sessionState != nil {
		req.Session = evaluator.RequestSession{
			ID: sessionState.ID,
		}
	}
	p := a.getMatchingPolicy(requestURL)
	if p != nil {
		for _, sp := range p.SubPolicies {
			req.CustomPolicies = append(req.CustomPolicies, sp.Rego...)
		}
	}

	ca, err := a.getDownstreamClientCA(p)
	if err != nil {
		return nil, err
	}
	req.ClientCA = ca

	return req, nil
}

func (a *Authorize) getDownstreamClientCA(policy *config.Policy) (string, error) {
	options := a.currentOptions.Load()
	switch {
	case policy != nil && policy.TLSDownstreamClientCA != "":
		bs, err := base64.StdEncoding.DecodeString(policy.TLSDownstreamClientCA)
		if err != nil {
			return "", err
		}
		return string(bs), nil
	case options.ClientCA != "":
		bs, err := base64.StdEncoding.DecodeString(options.ClientCA)
		if err != nil {
			return "", err
		}
		return string(bs), nil
	}
	return "", nil
}

func (a *Authorize) getMatchingPolicy(requestURL url.URL) *config.Policy {
	options := a.currentOptions.Load()

	for _, p := range options.GetAllPolicies() {
		if p.Matches(requestURL) {
			return &p
		}
	}

	return nil
}

func getHTTPRequestFromCheckRequest(req *envoy_service_auth_v2.CheckRequest) *http.Request {
	hattrs := req.GetAttributes().GetRequest().GetHttp()
	u := getCheckRequestURL(req)
	hreq := &http.Request{
		Method:     hattrs.GetMethod(),
		URL:        &u,
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

func getCheckRequestURL(req *envoy_service_auth_v2.CheckRequest) url.URL {
	h := req.GetAttributes().GetRequest().GetHttp()
	u := url.URL{
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
	u *user.User,
) {
	hdrs := getCheckRequestHeaders(in)
	hattrs := in.GetAttributes().GetRequest().GetHttp()
	evt := log.Info().Str("service", "authorize")
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
		evt = evt.Int("status", reply.Status)
		evt = evt.Str("message", reply.Message)
		evt = evt.Str("user", u.GetId())
		evt = evt.Str("email", u.GetEmail())
	}

	// potentially sensitive, only log if debug mode
	if zerolog.GlobalLevel() <= zerolog.DebugLevel {
		evt = evt.Interface("headers", hdrs)
	}

	evt.Msg("authorize check")
}

func stripQueryString(str string) string {
	if idx := strings.Index(str, "?"); idx != -1 {
		str = str[:idx]
	}
	return str
}
