package authorize

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sort"
	"strings"

	envoy_config_core_v3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	envoy_service_auth_v3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	envoy_type_v3 "github.com/envoyproxy/go-control-plane/envoy/type/v3"
	"github.com/golang/protobuf/ptypes/wrappers"
	"github.com/tniswong/go.rfcx/rfc7231"
	"google.golang.org/genproto/googleapis/rpc/status"
	"google.golang.org/grpc/codes"

	"github.com/pomerium/pomerium/authorize/evaluator"
	"github.com/pomerium/pomerium/internal/httputil"
	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/internal/telemetry/requestid"
	"github.com/pomerium/pomerium/internal/urlutil"
	"github.com/pomerium/pomerium/pkg/policy/criteria"
	"github.com/pomerium/pomerium/pkg/webauthnutil"
)

func (a *Authorize) handleResult(
	ctx context.Context,
	in *envoy_service_auth_v3.CheckRequest,
	request *evaluator.Request,
	result *evaluator.Result,
	isForwardAuthVerify bool,
) (*envoy_service_auth_v3.CheckResponse, error) {
	// when the user is unauthenticated it means they haven't
	// logged in yet, so redirect to authenticate
	if result.Allow.Reasons.Has(criteria.ReasonUserUnauthenticated) ||
		result.Deny.Reasons.Has(criteria.ReasonUserUnauthenticated) {
		return a.requireLoginResponse(ctx, in, request, isForwardAuthVerify)
	}

	// when the user's device is unauthenticated it means they haven't
	// registered a webauthn device yet, so redirect to the webauthn flow
	if result.Allow.Reasons.Has(criteria.ReasonDeviceUnauthenticated) ||
		result.Deny.Reasons.Has(criteria.ReasonDeviceUnauthenticated) {
		return a.requireWebAuthnResponse(ctx, in, request, result, isForwardAuthVerify)
	}

	// if there's a deny, the result is denied using the deny reasons.
	if result.Deny.Value {
		return a.handleResultDenied(ctx, in, request, result, isForwardAuthVerify, result.Deny.Reasons)
	}

	// if there's an allow, the result is allowed.
	if result.Allow.Value {
		return a.handleResultAllowed(ctx, in, result)
	}

	// otherwise, the result is denied using the allow reasons.
	return a.handleResultDenied(ctx, in, request, result, isForwardAuthVerify, result.Allow.Reasons)
}

func (a *Authorize) handleResultAllowed(
	ctx context.Context,
	in *envoy_service_auth_v3.CheckRequest,
	result *evaluator.Result,
) (*envoy_service_auth_v3.CheckResponse, error) {
	return a.okResponse(result.Headers), nil
}

func (a *Authorize) handleResultDenied(
	ctx context.Context,
	in *envoy_service_auth_v3.CheckRequest,
	request *evaluator.Request,
	result *evaluator.Result,
	isForwardAuthVerify bool,
	reasons criteria.Reasons,
) (*envoy_service_auth_v3.CheckResponse, error) {
	denyStatusCode := int32(http.StatusForbidden)
	denyStatusText := http.StatusText(http.StatusForbidden)

	switch {
	case reasons.Has(criteria.ReasonDeviceUnauthenticated):
		return a.requireWebAuthnResponse(ctx, in, request, result, isForwardAuthVerify)
	case reasons.Has(criteria.ReasonDeviceUnauthorized):
		denyStatusCode = httputil.StatusDeviceUnauthorized
		denyStatusText = httputil.DetailsText(httputil.StatusDeviceUnauthorized)
	case reasons.Has(criteria.ReasonRouteNotFound):
		denyStatusCode = http.StatusNotFound
		denyStatusText = httputil.DetailsText(http.StatusNotFound)
	case reasons.Has(criteria.ReasonInvalidClientCertificate):
		denyStatusCode = httputil.StatusInvalidClientCertificate
		denyStatusText = httputil.DetailsText(httputil.StatusInvalidClientCertificate)
	}

	return a.deniedResponse(ctx, in, denyStatusCode, denyStatusText, nil)
}

func (a *Authorize) okResponse(headers http.Header) *envoy_service_auth_v3.CheckResponse {
	var requestHeaders []*envoy_config_core_v3.HeaderValueOption
	for k, vs := range headers {
		requestHeaders = append(requestHeaders, mkHeader(k, strings.Join(vs, ","), false))
	}
	// ensure request headers are sorted by key for deterministic output
	sort.Slice(requestHeaders, func(i, j int) bool {
		return requestHeaders[i].Header.Key < requestHeaders[j].Header.Value
	})
	return &envoy_service_auth_v3.CheckResponse{
		Status: &status.Status{Code: int32(codes.OK), Message: "OK"},
		HttpResponse: &envoy_service_auth_v3.CheckResponse_OkResponse{
			OkResponse: &envoy_service_auth_v3.OkHttpResponse{
				Headers: requestHeaders,
			},
		},
	}
}

func (a *Authorize) deniedResponse(
	ctx context.Context,
	in *envoy_service_auth_v3.CheckRequest,
	code int32, reason string, headers map[string]string,
) (*envoy_service_auth_v3.CheckResponse, error) {
	respBody := []byte(reason)
	respHeader := []*envoy_config_core_v3.HeaderValueOption{}

	forwardAuthURL, _ := a.currentOptions.Load().GetForwardAuthURL()
	if forwardAuthURL == nil {
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
			BrandingOptions: a.currentOptions.Load().BrandingOptions,
		}
		httpErr.ErrorResponse(ctx, w, r)

		// transpose the go http response writer into a envoy response
		resp := w.Result()
		defer resp.Body.Close()
		var err error
		respBody, err = io.ReadAll(resp.Body)
		if err != nil {
			log.Error(ctx).Err(err).Msg("error executing error template")
			return nil, err
		}
		// convert go headers to envoy headers
		respHeader = append(respHeader, toEnvoyHeaders(resp.Header)...)
	} else {
		respHeader = append(respHeader, mkHeader("Content-Type", "text/plain", false))
	}

	// add any additional headers
	for k, v := range headers {
		respHeader = append(respHeader, mkHeader(k, v, false))
	}

	return &envoy_service_auth_v3.CheckResponse{
		Status: &status.Status{Code: int32(codes.PermissionDenied), Message: "Access Denied"},
		HttpResponse: &envoy_service_auth_v3.CheckResponse_DeniedResponse{
			DeniedResponse: &envoy_service_auth_v3.DeniedHttpResponse{
				Status: &envoy_type_v3.HttpStatus{
					Code: envoy_type_v3.StatusCode(code),
				},
				Headers: respHeader,
				Body:    string(respBody),
			},
		},
	}, nil
}

func (a *Authorize) requireLoginResponse(
	ctx context.Context,
	in *envoy_service_auth_v3.CheckRequest,
	request *evaluator.Request,
	isForwardAuthVerify bool,
) (*envoy_service_auth_v3.CheckResponse, error) {
	opts := a.currentOptions.Load()
	state := a.state.Load()
	authenticateURL, err := opts.GetAuthenticateURL()
	if err != nil {
		return nil, err
	}

	if !a.shouldRedirect(in) || isForwardAuthVerify {
		return a.deniedResponse(ctx, in, http.StatusUnauthorized, http.StatusText(http.StatusUnauthorized), nil)
	}

	signinURL := authenticateURL.ResolveReference(&url.URL{
		Path: "/.pomerium/sign_in",
	})
	q := signinURL.Query()

	// always assume https scheme
	checkRequestURL := getCheckRequestURL(in)
	checkRequestURL.Scheme = "https"

	q.Set(urlutil.QueryRedirectURI, checkRequestURL.String())
	idp, err := opts.GetIdentityProviderForPolicy(request.Policy)
	if err != nil {
		return nil, err
	}
	q.Set(urlutil.QueryIdentityProviderID, idp.GetId())
	signinURL.RawQuery = q.Encode()
	redirectTo := urlutil.NewSignedURL(state.sharedKey, signinURL).String()

	return a.deniedResponse(ctx, in, http.StatusFound, "Login", map[string]string{
		"Location": redirectTo,
	})
}

func (a *Authorize) requireWebAuthnResponse(
	ctx context.Context,
	in *envoy_service_auth_v3.CheckRequest,
	request *evaluator.Request,
	result *evaluator.Result,
	isForwardAuthVerify bool,
) (*envoy_service_auth_v3.CheckResponse, error) {
	opts := a.currentOptions.Load()
	state := a.state.Load()
	authenticateURL, err := opts.GetAuthenticateURL()
	if err != nil {
		return nil, err
	}

	if !a.shouldRedirect(in) || isForwardAuthVerify {
		return a.deniedResponse(ctx, in, http.StatusUnauthorized, http.StatusText(http.StatusUnauthorized), nil)
	}

	signinURL := authenticateURL.ResolveReference(&url.URL{
		Path: "/.pomerium/webauthn",
	})
	q := signinURL.Query()

	// always assume https scheme
	checkRequestURL := getCheckRequestURL(in)
	checkRequestURL.Scheme = "https"

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
	signinURL.RawQuery = q.Encode()
	redirectTo := urlutil.NewSignedURL(state.sharedKey, signinURL).String()

	return a.deniedResponse(ctx, in, http.StatusFound, "Login", map[string]string{
		"Location": redirectTo,
	})
}

func mkHeader(k, v string, shouldAppend bool) *envoy_config_core_v3.HeaderValueOption {
	return &envoy_config_core_v3.HeaderValueOption{
		Header: &envoy_config_core_v3.HeaderValue{
			Key:   k,
			Value: v,
		},
		Append: &wrappers.BoolValue{
			Value: shouldAppend,
		},
	}
}

func toEnvoyHeaders(headers http.Header) []*envoy_config_core_v3.HeaderValueOption {
	var ks []string
	for k := range headers {
		ks = append(ks, k)
	}
	sort.Strings(ks)

	envoyHeaders := make([]*envoy_config_core_v3.HeaderValueOption, 0, len(headers))
	for _, k := range ks {
		envoyHeaders = append(envoyHeaders, mkHeader(k, headers.Get(k), false))
	}
	return envoyHeaders
}

// userInfoEndpointURL returns the user info endpoint url which can be used to debug the user's
// session that lives on the authenticate service.
func (a *Authorize) userInfoEndpointURL(in *envoy_service_auth_v3.CheckRequest) (*url.URL, error) {
	opts := a.currentOptions.Load()
	authenticateURL, err := opts.GetAuthenticateURL()
	if err != nil {
		return nil, err
	}
	debugEndpoint := authenticateURL.ResolveReference(&url.URL{Path: "/.pomerium/"})

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

func (a *Authorize) shouldRedirect(in *envoy_service_auth_v3.CheckRequest) bool {
	requestHeaders := in.GetAttributes().GetRequest().GetHttp().GetHeaders()
	if requestHeaders == nil {
		return true
	}

	if strings.HasPrefix(requestHeaders["content-type"], "application/grpc") {
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
