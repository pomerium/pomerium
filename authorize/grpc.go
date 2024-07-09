package authorize

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	envoy_service_auth_v3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	typev3 "github.com/envoyproxy/go-control-plane/envoy/type/v3"
	"google.golang.org/genproto/googleapis/rpc/status"
	"google.golang.org/protobuf/types/known/structpb"

	"github.com/pomerium/pomerium/authorize/evaluator"
	"github.com/pomerium/pomerium/config/envoyconfig"
	"github.com/pomerium/pomerium/internal/httputil"
	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/internal/sessions"
	"github.com/pomerium/pomerium/internal/telemetry/trace"
	"github.com/pomerium/pomerium/internal/urlutil"
	"github.com/pomerium/pomerium/pkg/contextutil"
	"github.com/pomerium/pomerium/pkg/grpc/user"
	"github.com/pomerium/pomerium/pkg/storage"
	"github.com/pomerium/pomerium/pkg/telemetry/requestid"
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

	if hreq.Header.Get("X-Pomerium-Check-Route") != "" {
		body, _ := json.Marshal(in.GetAttributes().GetContextExtensions())
		if err := urlutil.NewSignedURL(state.sharedKey, urlutil.GetAbsoluteURL(hreq)).Validate(); err != nil {
			log.Ctx(ctx).Info().Msg("ignoring route check request with missing or invalid signature")
			return nil, err
		}
		return &envoy_service_auth_v3.CheckResponse{
			Status: &status.Status{
				// return a non-200 code to envoy to deny the request
				Code: 299,
			},
			HttpResponse: &envoy_service_auth_v3.CheckResponse_DeniedResponse{
				DeniedResponse: &envoy_service_auth_v3.DeniedHttpResponse{
					// then return code 200 to the caller
					Status: &typev3.HttpStatus{Code: 200},
					Headers: toEnvoyHeaders(http.Header{
						"Content-Type": {"application/json"},
					}),
					Body: string(body),
				},
			},
		}, nil
	}

	routeID, ok := getRouteIDFromCheckRequest(in)
	if !ok {
		log.Ctx(ctx).Error().
			Str("url", hreq.URL.String()).
			Msg("bug: no route ID found in check request")
		return nil, fmt.Errorf("route configuration error")
	}
	sessionState, _ := state.sessionStore.LoadSessionState(hreq, routeID)

	var s sessionOrServiceAccount
	var u *user.User
	var err error
	if sessionState != nil {
		s, err = a.getDataBrokerSessionOrServiceAccount(ctx, sessionState.ID, sessionState.DatabrokerRecordVersion)
		if err != nil {
			log.Warn(ctx).Err(err).Msg("clearing session due to missing or invalid session or service account")
			sessionState = nil
		}
	}
	if sessionState != nil && s != nil {
		u, _ = a.getDataBrokerUser(ctx, s.GetUserId()) // ignore any missing user error
	}

	req, err := a.getEvaluatorRequestFromCheckRequest(ctx, in, sessionState)
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
	ctx context.Context,
	in *envoy_service_auth_v3.CheckRequest,
	sessionState *sessions.State,
) (*evaluator.Request, error) {
	requestURL := getCheckRequestURL(in)
	attrs := in.GetAttributes()
	clientCertMetadata := attrs.GetMetadataContext().GetFilterMetadata()["com.pomerium.client-certificate-info"]
	req := &evaluator.Request{
		IsInternal: envoyconfig.ExtAuthzContextExtensionsIsInternal(attrs.GetContextExtensions()),
		HTTP: evaluator.NewRequestHTTP(
			attrs.GetRequest().GetHttp().GetMethod(),
			requestURL,
			getCheckRequestHeaders(in),
			getClientCertificateInfo(ctx, clientCertMetadata),
			attrs.GetSource().GetAddress().GetSocketAddress().GetAddress(),
		),
	}
	if sessionState != nil {
		req.Session = evaluator.RequestSession{
			ID: sessionState.ID,
		}
	}
	state := a.state.Load()
	req.Policy, _ = state.idpCache.GetPolicyByID(envoyconfig.ExtAuthzContextExtensionsRouteID(attrs.GetContextExtensions()))
	return req, nil
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
		hdrs[httputil.CanonicalHeaderKey(k)] = v
	}
	return hdrs
}

func getRouteIDFromCheckRequest(req *envoy_service_auth_v3.CheckRequest) (uint64, bool) {
	idStr := req.GetAttributes().GetContextExtensions()["route_id"]
	if idStr == "" {
		return 0, false
	}
	id, err := strconv.ParseUint(idStr, 10, 64)
	if err != nil {
		return 0, false
	}
	return id, true
}

func getCheckRequestURL(req *envoy_service_auth_v3.CheckRequest) url.URL {
	h := req.GetAttributes().GetRequest().GetHttp()
	u := url.URL{
		Scheme: h.GetScheme(),
		Host:   h.GetHost(),
	}
	u.Host = urlutil.GetDomainsForURL(&u, false)[0]
	// envoy sends the query string as part of the path
	path := h.GetPath()
	if idx := strings.Index(path, "?"); idx != -1 {
		u.RawPath, u.RawQuery = path[:idx], path[idx+1:]
		u.RawQuery = u.Query().Encode()
	} else {
		u.RawPath = path
	}
	u.Path, _ = url.PathUnescape(u.RawPath)
	return u
}

// getClientCertificateInfo translates from the client certificate Envoy
// metadata to the ClientCertificateInfo type.
func getClientCertificateInfo(
	ctx context.Context, metadata *structpb.Struct,
) evaluator.ClientCertificateInfo {
	var c evaluator.ClientCertificateInfo
	if metadata == nil {
		return c
	}
	c.Presented = metadata.Fields["presented"].GetBoolValue()
	escapedChain := metadata.Fields["chain"].GetStringValue()
	if escapedChain == "" {
		// No validated client certificate.
		return c
	}

	chain, err := url.QueryUnescape(escapedChain)
	if err != nil {
		log.Warn(ctx).Str("chain", escapedChain).Err(err).
			Msg(`received unexpected client certificate "chain" value`)
		return c
	}

	// Split the chain into the leaf and any intermediate certificates.
	p, rest := pem.Decode([]byte(chain))
	if p == nil {
		log.Warn(ctx).Str("chain", escapedChain).
			Msg(`received unexpected client certificate "chain" value (no PEM block found)`)
		return c
	}
	c.Leaf = string(pem.EncodeToMemory(p))
	c.Intermediates = string(rest)
	return c
}
