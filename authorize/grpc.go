package authorize

import (
	"context"
	"io"
	"net/http"
	"net/url"
	"strings"

	envoy_service_auth_v3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"

	"github.com/pomerium/pomerium/authorize/evaluator"
	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/httputil"
	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/internal/sessions"
	"github.com/pomerium/pomerium/internal/telemetry/trace"
	"github.com/pomerium/pomerium/internal/urlutil"
)

// Check implements the envoy auth server gRPC endpoint.
func (a *Authorize) Check(ctx context.Context, in *envoy_service_auth_v3.CheckRequest) (out *envoy_service_auth_v3.CheckResponse, err error) {
	ctx, span := trace.StartSpan(ctx, "authorize.grpc.Check")
	defer span.End()

	// wait for the initial sync to complete so that data is available for evaluation
	if err := a.WaitForInitialSync(ctx); err != nil {
		return nil, err
	}

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

	s, u, err := a.forceSync(ctx, sessionState)
	if err != nil {
		log.Warn(ctx).Err(err).Msg("clearing session due to force sync failed")
		sessionState = nil
	}

	req, err := a.getEvaluatorRequestFromCheckRequest(in, sessionState)
	if err != nil {
		log.Warn(ctx).Err(err).Msg("error building evaluator request")
		return nil, err
	}

	// take the state lock here so we don't update while evaluating
	a.stateLock.RLock()
	res, err := state.evaluator.Evaluate(ctx, req)
	a.stateLock.RUnlock()
	if err != nil {
		log.Error(ctx).Err(err).Msg("error during OPA evaluation")
		return nil, err
	}
	defer func() {
		a.logAuthorizeCheck(ctx, in, out, res, s, u)
	}()

	isForwardAuthVerify := isForwardAuth && hreq.URL.Path == "/verify"

	// if there's a deny, the result is denied using the deny reasons.
	if res.Deny.Value {
		return a.handleResultDenied(ctx, in, req, res, isForwardAuthVerify, res.Deny.Reasons)
	}

	// if there's an allow, the result is allowed.
	if res.Allow.Value {
		return a.handleResultAllowed(ctx, in, res)
	}

	// otherwise, the result is denied using the allow reasons.
	return a.handleResultDenied(ctx, in, req, res, isForwardAuthVerify, res.Allow.Reasons)
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
func (a *Authorize) isForwardAuth(req *envoy_service_auth_v3.CheckRequest) bool {
	opts := a.currentOptions.Load()

	forwardAuthURL, err := opts.GetForwardAuthURL()
	if err != nil || forwardAuthURL == nil {
		return false
	}

	checkURL := getCheckRequestURL(req)

	return urlutil.StripPort(checkURL.Host) == urlutil.StripPort(forwardAuthURL.Host)
}

func (a *Authorize) getEvaluatorRequestFromCheckRequest(
	in *envoy_service_auth_v3.CheckRequest,
	sessionState *sessions.State,
) (*evaluator.Request, error) {
	requestURL := getCheckRequestURL(in)
	req := &evaluator.Request{
		HTTP: evaluator.NewRequestHTTP(
			in.GetAttributes().GetRequest().GetHttp().GetMethod(),
			requestURL,
			getCheckRequestHeaders(in),
			getPeerCertificate(in),
			in.GetAttributes().GetSource().GetAddress().GetSocketAddress().GetAddress(),
		),
	}
	if sessionState != nil {
		req.Session = evaluator.RequestSession{
			ID: sessionState.ID,
		}
	}
	req.Policy = a.getMatchingPolicy(requestURL)
	return req, nil
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

func getHTTPRequestFromCheckRequest(req *envoy_service_auth_v3.CheckRequest) *http.Request {
	hattrs := req.GetAttributes().GetRequest().GetHttp()
	u := getCheckRequestURL(req)
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
		hdrs[http.CanonicalHeaderKey(k)] = v
	}
	return hdrs
}

func getCheckRequestURL(req *envoy_service_auth_v3.CheckRequest) url.URL {
	h := req.GetAttributes().GetRequest().GetHttp()
	u := url.URL{
		Scheme: h.GetScheme(),
		Host:   h.GetHost(),
	}
	u.Host = urlutil.GetDomainsForURL(u)[0]
	// envoy sends the query string as part of the path
	path := h.GetPath()
	if idx := strings.Index(path, "?"); idx != -1 {
		u.RawPath, u.RawQuery = path[:idx], path[idx+1:]
	} else {
		u.RawPath = path
	}
	u.Path, _ = url.PathUnescape(u.RawPath)
	return u
}

// getPeerCertificate gets the PEM-encoded peer certificate from the check request
func getPeerCertificate(in *envoy_service_auth_v3.CheckRequest) string {
	// ignore the error as we will just return the empty string in that case
	cert, _ := url.QueryUnescape(in.GetAttributes().GetSource().GetCertificate())
	return cert
}
