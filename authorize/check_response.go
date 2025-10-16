package authorize

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sort"
	"strings"

	envoy_config_core_v3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	envoy_service_auth_v3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	envoy_type_v3 "github.com/envoyproxy/go-control-plane/envoy/type/v3"
	"github.com/tniswong/go.rfcx/rfc7231"
	"google.golang.org/genproto/googleapis/rpc/status"
	"google.golang.org/grpc/codes"

	"github.com/pomerium/pomerium/authorize/checkrequest"
	"github.com/pomerium/pomerium/authorize/evaluator"
	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/httputil"
	"github.com/pomerium/pomerium/internal/jsonrpc"
	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/internal/mcp"
	"github.com/pomerium/pomerium/internal/urlutil"
	"github.com/pomerium/pomerium/pkg/endpoints"
	"github.com/pomerium/pomerium/pkg/policy/criteria"
	"github.com/pomerium/pomerium/pkg/telemetry/requestid"
	"github.com/pomerium/pomerium/pkg/webauthnutil"
)

func (a *Authorize) handleResult(
	ctx context.Context,
	in *envoy_service_auth_v3.CheckRequest,
	request *evaluator.Request,
	result *evaluator.Result,
) (*envoy_service_auth_v3.CheckResponse, error) {
	// If a client certificate is required, but the client did not provide a
	// valid certificate, deny right away. Do not redirect to authenticate.
	if invalidClientCertReason(result.Deny.Reasons) {
		return a.handleResultDenied(ctx, in, request, result, result.Deny.Reasons)
	}

	// when the user is unauthenticated it means they haven't
	// logged in yet, so redirect to authenticate
	if result.HasReason(criteria.ReasonUserUnauthenticated) {
		return a.requireLoginResponse(ctx, in, request)
	}

	// when the user's device is unauthenticated it means they haven't
	// registered a webauthn device yet, so redirect to the webauthn flow
	if result.HasReason(criteria.ReasonDeviceUnauthenticated) {
		return a.requireWebAuthnResponse(ctx, in, request, result)
	}

	// if there's a deny, the result is denied using the deny reasons.
	if result.Deny.Value {
		return a.handleResultDenied(ctx, in, request, result, result.Deny.Reasons)
	}

	// if there's an allow, the result is allowed.
	if result.Allow.Value {
		return a.handleResultAllowed(ctx, in, result)
	}

	// otherwise, the result is denied using the allow reasons.
	return a.handleResultDenied(ctx, in, request, result, result.Allow.Reasons)
}

func (a *Authorize) handleResultAllowed(
	_ context.Context,
	_ *envoy_service_auth_v3.CheckRequest,
	result *evaluator.Result,
) (*envoy_service_auth_v3.CheckResponse, error) {
	return a.okResponse(result.Headers, result.HeadersToRemove), nil
}

func (a *Authorize) handleResultDenied(
	ctx context.Context,
	in *envoy_service_auth_v3.CheckRequest,
	request *evaluator.Request,
	result *evaluator.Result,
	reasons criteria.Reasons,
) (*envoy_service_auth_v3.CheckResponse, error) {
	denyStatusCode := int32(http.StatusForbidden)
	denyStatusText := http.StatusText(http.StatusForbidden)
	var headers http.Header

	switch {
	case reasons.Has(criteria.ReasonDeviceUnauthenticated):
		return a.requireWebAuthnResponse(ctx, in, request, result)
	case reasons.Has(criteria.ReasonDeviceUnauthorized):
		denyStatusCode = httputil.StatusDeviceUnauthorized
		denyStatusText = httputil.DetailsText(httputil.StatusDeviceUnauthorized)
	case reasons.Has(criteria.ReasonRouteNotFound):
		denyStatusCode = http.StatusNotFound
		denyStatusText = httputil.DetailsText(http.StatusNotFound)
	case invalidClientCertReason(reasons):
		denyStatusCode = httputil.StatusInvalidClientCertificate
		denyStatusText = httputil.DetailsText(httputil.StatusInvalidClientCertificate)
	case request.MCP.Method != "":
		return deniedResponseForMCP(ctx, request.MCP.ID), nil
	case request.Policy.IsMCPServer():
		denyStatusCode = http.StatusUnauthorized
		denyStatusText = httputil.DetailsText(http.StatusUnauthorized)
		headers = make(http.Header)
		err := mcp.Set401WWWAuthenticateHeader(headers, request.HTTP.Host)
		if err != nil {
			return nil, err
		}
	}

	return a.deniedResponse(ctx, in, denyStatusCode, denyStatusText, headers)
}

func invalidClientCertReason(reasons criteria.Reasons) bool {
	return reasons.Has(criteria.ReasonClientCertificateRequired) ||
		reasons.Has(criteria.ReasonInvalidClientCertificate)
}

func (a *Authorize) okResponse(headersToSet http.Header, headersToRemove []string) *envoy_service_auth_v3.CheckResponse {
	return &envoy_service_auth_v3.CheckResponse{
		Status: &status.Status{Code: int32(codes.OK), Message: "OK"},
		HttpResponse: &envoy_service_auth_v3.CheckResponse_OkResponse{
			OkResponse: &envoy_service_auth_v3.OkHttpResponse{
				Headers:         toEnvoyHeaders(headersToSet),
				HeadersToRemove: headersToRemove,
			},
		},
	}
}

func deniedResponseForMCP(
	ctx context.Context,
	id jsonrpc.ID,
) *envoy_service_auth_v3.CheckResponse {
	requestID := requestid.FromContext(ctx)
	respBody, _ := json.Marshal(
		jsonrpc.NewErrorResponse(
			jsonrpc.ErrorCodeInvalidParams,
			id,
			fmt.Sprintf("access denied, please see the authorization log for the request %s for details", requestID),
			map[string]any{
				"request_id": requestID,
			},
		),
	)
	headers := http.Header{}
	headers.Set("Content-Type", "application/json")
	headers.Set("Cache-Control", "no-cache")

	return mkDeniedCheckResponse(
		http.StatusOK,
		headers,
		string(respBody),
	)
}

func (a *Authorize) deniedResponse(
	ctx context.Context,
	in *envoy_service_auth_v3.CheckRequest,
	code int32, reason string, headers http.Header,
) (*envoy_service_auth_v3.CheckResponse, error) {
	if headers == nil {
		headers = make(http.Header)
	}

	var respBody []byte

	hdrs := in.GetAttributes().GetRequest().GetHttp().GetHeaders()
	userAgent := getHeader(hdrs, "User-Agent")
	switch {
	case strings.Contains(userAgent, "kubernetes/"):
		message := reason
		var statusReason string
		switch code {
		case http.StatusUnauthorized:
			statusReason = "Unauthorized"
		case http.StatusForbidden:
			statusReason = "Forbidden"
		case http.StatusNotFound:
			statusReason = "NotFound"
		case httputil.StatusDeviceUnauthorized, httputil.StatusInvalidClientCertificate:
			statusReason = "Unauthorized"
			message = httputil.DetailsText(int(code))
		default:
			statusReason = "" // StatusReasonUnknown
		}
		respBody, _ = json.Marshal(map[string]any{
			"apiVersion": "v1",
			"kind":       "Status",
			"status":     "Failure",    // one of "Success" or "Failure"
			"message":    message,      // user-facing message
			"reason":     statusReason, // must correspond to k8s StatusReason strings
			"code":       code,         // http code
		})
		headers.Set("Content-Type", "application/json")
	case checkrequest.GetURL(in).Path == "/robots.txt":
		code = 200
		respBody = []byte("User-agent: *\nDisallow: /")
		headers.Set("Content-Type", "text/plain")
	case isJSONWebRequest(in):
		respBody, _ = json.Marshal(map[string]any{
			"error":      reason,
			"request_id": requestid.FromContext(ctx),
		})
		headers.Set("Content-Type", "application/json")
	case isGRPCRequest(in):
		return deniedResponseForGRPC(code, reason, headers), nil
	case isGRPCWebRequest(in):
		return deniedResponseForGRPCWeb(code, reason, headers), nil
	default:
		// create a http response writer recorder
		w := httptest.NewRecorder()
		r := getHTTPRequestFromCheckRequest(in)

		// build the user info / debug endpoint
		debugEndpoint, _ := a.userInfoEndpointURL(in) // if there's an error, we just wont display it

		// run the request through our go error handler
		httpErr := httputil.HTTPError{
			Status:          int(code),
			Err:             errors.New(reason),
			DebugURL:        debugEndpoint,
			RequestID:       requestid.FromContext(ctx),
			BrandingOptions: a.currentConfig.Load().Options.BrandingOptions,
		}
		httpErr.ErrorResponse(ctx, w, r)

		// transpose the go http response writer into a envoy response
		resp := w.Result()
		defer resp.Body.Close()

		var err error
		respBody, err = io.ReadAll(resp.Body)
		if err != nil {
			log.Ctx(ctx).Error().Err(err).Msg("error executing error template")
			return nil, err
		}
		for k, vs := range resp.Header {
			headers[k] = vs
		}
	}

	return mkDeniedCheckResponse(code, headers, string(respBody)), nil
}

func (a *Authorize) requireLoginResponse(
	ctx context.Context,
	in *envoy_service_auth_v3.CheckRequest,
	request *evaluator.Request,
) (*envoy_service_auth_v3.CheckResponse, error) {
	options := a.currentConfig.Load().Options
	state := a.state.Load()

	if !a.shouldRedirect(in, request) {
		return a.deniedResponse(ctx, in, http.StatusUnauthorized, "Unauthenticated", nil)
	}

	idp, err := options.GetIdentityProviderForPolicy(request.Policy)
	if err != nil {
		return nil, err
	}

	// always assume https scheme
	checkRequestURL := checkrequest.GetURL(in)
	checkRequestURL.Scheme = "https"
	var signInURLQuery url.Values

	headers := http.Header{}
	if id := in.GetAttributes().GetRequest().GetHttp().GetHeaders()["traceparent"]; id != "" {
		signInURLQuery = url.Values{}
		signInURLQuery.Add("pomerium_traceparent", id)
	}
	var additionalHosts []string
	if request.Policy != nil {
		additionalHosts = request.Policy.DependsOn
	}
	redirectTo, err := state.authenticateFlow.AuthenticateSignInURL(
		ctx, signInURLQuery, &checkRequestURL, idp.GetId(), additionalHosts)
	if err != nil {
		return nil, err
	}
	headers["Location"] = []string{redirectTo}

	return a.deniedResponse(ctx, in, http.StatusFound, "Login", headers)
}

func (a *Authorize) requireWebAuthnResponse(
	ctx context.Context,
	in *envoy_service_auth_v3.CheckRequest,
	request *evaluator.Request,
	result *evaluator.Result,
) (*envoy_service_auth_v3.CheckResponse, error) {
	opts := a.currentConfig.Load().Options
	state := a.state.Load()

	// always assume https scheme
	checkRequestURL := checkrequest.GetURL(in)
	checkRequestURL.Scheme = "https"

	// If we're already on a webauthn route, return OK.
	// https://github.com/pomerium/pomerium-console/issues/3210
	if checkRequestURL.Path == urlutil.WebAuthnURLPath || checkRequestURL.Path == urlutil.DeviceEnrolledPath {
		return a.okResponse(result.Headers, result.HeadersToRemove), nil
	}

	if !a.shouldRedirect(in, request) {
		return a.deniedResponse(ctx, in, http.StatusUnauthorized, "Unauthenticated", nil)
	}

	q := url.Values{}
	if deviceType, ok := result.Allow.AdditionalData["device_type"].(string); ok {
		q.Set(urlutil.QueryDeviceType, deviceType)
	} else if deviceType, ok := result.Deny.AdditionalData["device_type"].(string); ok {
		q.Set(urlutil.QueryDeviceType, deviceType)
	} else {
		q.Set(urlutil.QueryDeviceType, webauthnutil.DefaultDeviceType)
	}
	q.Set(urlutil.QueryRedirectURI, checkRequestURL.String())
	idp, err := opts.GetIdentityProviderForPolicy(request.Policy)
	if err != nil {
		return nil, err
	}
	q.Set(urlutil.QueryIdentityProviderID, idp.GetId())
	signinURL := urlutil.WebAuthnURL(getHTTPRequestFromCheckRequest(in), &checkRequestURL, state.sharedKey, q)
	return a.deniedResponse(ctx, in, http.StatusFound, "Login", http.Header{
		"Location": {signinURL},
	})
}

func mkDeniedCheckResponse(httpStatusCode int32, headers http.Header, body string) *envoy_service_auth_v3.CheckResponse {
	return &envoy_service_auth_v3.CheckResponse{
		Status: &status.Status{Code: int32(codes.PermissionDenied), Message: "Access Denied"},
		HttpResponse: &envoy_service_auth_v3.CheckResponse_DeniedResponse{
			DeniedResponse: &envoy_service_auth_v3.DeniedHttpResponse{
				Status: &envoy_type_v3.HttpStatus{
					Code: envoy_type_v3.StatusCode(httpStatusCode),
				},
				Headers: toEnvoyHeaders(headers),
				Body:    body,
			},
		},
	}
}

func mkHeader(k, v string) *envoy_config_core_v3.HeaderValueOption {
	return &envoy_config_core_v3.HeaderValueOption{
		Header: &envoy_config_core_v3.HeaderValue{
			Key:   k,
			Value: v,
		},
		AppendAction: envoy_config_core_v3.HeaderValueOption_OVERWRITE_IF_EXISTS_OR_ADD,
	}
}

func toEnvoyHeaders(headers http.Header) []*envoy_config_core_v3.HeaderValueOption {
	envoyHeaders := make([]*envoy_config_core_v3.HeaderValueOption, 0, len(headers))
	for k, vs := range maps.All(headers) {
		envoyHeaders = append(envoyHeaders, mkHeader(k, strings.Join(vs, ",")))
	}
	sort.Slice(envoyHeaders, func(i, j int) bool {
		return envoyHeaders[i].GetHeader().GetKey() < envoyHeaders[j].GetHeader().GetKey()
	})
	return envoyHeaders
}

// userInfoEndpointURL returns the user info endpoint url which can be used to debug the user's
// session that lives on the authenticate service.
func (a *Authorize) userInfoEndpointURL(in *envoy_service_auth_v3.CheckRequest) (*url.URL, error) {
	opts := a.currentConfig.Load().Options
	authenticateURL, err := opts.GetAuthenticateURL()
	if err != nil {
		return nil, err
	}
	debugEndpoint := authenticateURL.ResolveReference(&url.URL{Path: endpoints.PathPomeriumDashboard + "/"})

	r := getHTTPRequestFromCheckRequest(in)
	redirectURL := urlutil.GetAbsoluteURL(r).String()
	if ref := r.Header.Get(httputil.HeaderReferrer); ref != "" {
		redirectURL = ref
	}

	debugEndpoint = debugEndpoint.ResolveReference(&url.URL{
		RawQuery: url.Values{
			urlutil.QueryRedirectURI: {redirectURL},
		}.Encode(),
	})

	return urlutil.NewSignedURL(a.state.Load().sharedKey, debugEndpoint).Sign(), nil
}

func (a *Authorize) shouldRedirect(in *envoy_service_auth_v3.CheckRequest, request *evaluator.Request) bool {
	if a.currentConfig.Load().Options.IsRuntimeFlagSet(config.RuntimeFlagMCP) {
		if request.Policy.IsMCPServer() {
			return false
		}
	}

	requestHeaders := in.GetAttributes().GetRequest().GetHttp().GetHeaders()
	if requestHeaders == nil {
		return true
	}

	if isGRPCRequest(in) {
		return false
	}

	accept, err := rfc7231.ParseAccept(requestHeaders["accept"])
	if err != nil {
		return true
	}

	mediaType, ok := accept.MostAcceptable([]string{
		"text/html",
		"application/json",
		"text/plain",
		"application/grpc-web-text",
		"application/grpc-web+proto",
		"application/grpc+proto",
	})
	if !ok {
		return true
	}

	return mediaType == "text/html"
}

func isJSONWebRequest(in *envoy_service_auth_v3.CheckRequest) bool {
	hdrs := in.GetAttributes().GetRequest().GetHttp().GetHeaders()
	if hdrs == nil {
		return false
	}

	v := getHeader(hdrs, "Accept")
	if v == "" {
		return false
	}

	accept, err := rfc7231.ParseAccept(v)
	if err != nil {
		return false
	}

	mediaType, _ := accept.MostAcceptable([]string{
		"text/html",
		"application/json",
	})
	return mediaType == "application/json"
}

func getHeader(hdrs map[string]string, key string) string {
	for k, v := range hdrs {
		if strings.EqualFold(k, key) {
			return v
		}
	}
	return ""
}
