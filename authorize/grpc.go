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
	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/internal/sessions"
	"github.com/pomerium/pomerium/internal/telemetry/requestid"
	"github.com/pomerium/pomerium/internal/telemetry/trace"
	"github.com/pomerium/pomerium/internal/urlutil"
	"github.com/pomerium/pomerium/pkg/contextutil"
	"github.com/pomerium/pomerium/pkg/grpc/user"
	"github.com/pomerium/pomerium/pkg/storage"
)

// Check implements the envoy auth server gRPC endpoint.
func (a *Authorize) Check(ctx context.Context, in *envoy_service_auth_v3.CheckRequest) (*envoy_service_auth_v3.CheckResponse, error) {
	ctx, span := trace.StartSpan(ctx, "authorize.grpc.Check")
	defer span.End()

	querier := storage.NewTracingQuerier(
		storage.NewCachingQuerier(
			storage.NewCachingQuerier(
				storage.NewQuerier(a.state.Load().dataBrokerClient),
				a.globalCache,
			),
			storage.NewLocalCache(),
		),
	)
	ctx = storage.WithQuerier(ctx, querier)

	state := a.state.Load()

	// convert the incoming envoy-style http request into a go-style http request
	hreq := getHTTPRequestFromCheckRequest(in)
	ctx = requestid.WithValue(ctx, requestid.FromHTTPHeader(hreq.Header))

	sessionState, _ := state.sessionStore.LoadSessionState(hreq)

	var s sessionOrServiceAccount
	var u *user.User
	var err error
	if sessionState != nil {
		s, err = a.getDataBrokerSessionOrServiceAccount(ctx, sessionState.ID, sessionState.DatabrokerRecordVersion)
		if err != nil {
			log.Warn(ctx).Err(err).Msg("clearing session due to missing session or service account")
			sessionState = nil
		}
	}
	if sessionState != nil && s != nil {
		u, _ = a.getDataBrokerUser(ctx, s.GetUserId()) // ignore any missing user error
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

	// if show error details is enabled, attach the policy evaluation traces
	if req.Policy != nil && req.Policy.ShowErrorDetails {
		ctx = contextutil.WithPolicyEvaluationTraces(ctx, res.Traces)
	}

	resp, err := a.handleResult(ctx, in, req, res)
	if err != nil {
		log.Error(ctx).Err(err).Str("request-id", requestid.FromContext(ctx)).Msg("grpc check ext_authz_error")
	}
	a.logAuthorizeCheck(ctx, in, resp, res, s, u)
	return resp, err
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
	u.Host = urlutil.GetDomainsForURL(&u)[0]
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
