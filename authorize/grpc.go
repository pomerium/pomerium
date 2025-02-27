package authorize

import (
	"context"
	"encoding/pem"
	"io"
	"net/http"
	"net/url"
	"strings"

	envoy_service_auth_v3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	"github.com/pomerium/pomerium/authorize/evaluator"
	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/config/envoyconfig"

	"github.com/pomerium/pomerium/internal/httputil"
	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/internal/sessions"
	"github.com/pomerium/pomerium/internal/urlutil"
	"github.com/pomerium/pomerium/pkg/telemetry/requestid"
	"google.golang.org/protobuf/types/known/structpb"
)

// Check implements the envoy auth server gRPC endpoint.
func (a *Authorize) Check(ctx context.Context, in *envoy_service_auth_v3.CheckRequest) (*envoy_service_auth_v3.CheckResponse, error) {
	ctx, span := a.tracer.Start(ctx, "authorize.grpc.Check")
	defer span.End()

	state := a.state.Load()

	// convert the incoming envoy-style http request into a go-style http request
	hreq := getHTTPRequestFromCheckRequest(in)
	requestID := requestid.FromHTTPHeader(hreq.Header)
	ctx = requestid.WithValue(ctx, requestID)

	sessionState, _ := state.sessionStore.LoadSessionStateAndCheckIDP(hreq)

	req, err := a.getEvaluatorRequestFromCheckRequest(ctx, in, sessionState)
	if err != nil {
		log.Ctx(ctx).Error().Err(err).Str("request-id", requestID).Msg("error building evaluator request")
		return nil, err
	}

	res, err := a.evaluate(ctx, req, sessionState)
	if err != nil {
		return nil, err
	}

	resp, err := a.handleResult(ctx, in, req, res)
	if err != nil {
		log.Ctx(ctx).Error().Err(err).Str("request-id", requestID).Msg("grpc check ext_authz_error")
	}
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
	req.Policy = a.getMatchingPolicy(envoyconfig.ExtAuthzContextExtensionsRouteID(attrs.GetContextExtensions()))
	return req, nil
}

func (a *Authorize) getMatchingPolicy(routeID uint64) *config.Policy {
	options := a.currentOptions.Load()

	for p := range options.GetAllPolicies() {
		id, _ := p.RouteID()
		if id == routeID {
			return p
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
		hdrs[httputil.CanonicalHeaderKey(k)] = v
	}
	return hdrs
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
		log.Ctx(ctx).Error().Str("chain", escapedChain).Err(err).
			Msg(`received unexpected client certificate "chain" value`)
		return c
	}

	// Split the chain into the leaf and any intermediate certificates.
	p, rest := pem.Decode([]byte(chain))
	if p == nil {
		log.Ctx(ctx).Error().Str("chain", escapedChain).
			Msg(`received unexpected client certificate "chain" value (no PEM block found)`)
		return c
	}
	c.Leaf = string(pem.EncodeToMemory(p))
	c.Intermediates = string(rest)
	return c
}
