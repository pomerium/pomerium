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
	"google.golang.org/genproto/googleapis/rpc/status"
	"google.golang.org/grpc/codes"

	"github.com/pomerium/pomerium/authorize/evaluator"
	"github.com/pomerium/pomerium/internal/httputil"
	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/internal/telemetry/requestid"
	"github.com/pomerium/pomerium/internal/urlutil"
)

func (a *Authorize) okResponse(reply *evaluator.Result) *envoy_service_auth_v3.CheckResponse {
	var requestHeaders []*envoy_config_core_v3.HeaderValueOption
	for k, vs := range reply.Headers {
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
	var details string
	switch code {
	case httputil.StatusInvalidClientCertificate:
		details = httputil.StatusText(httputil.StatusInvalidClientCertificate)
	case http.StatusForbidden:
		details = http.StatusText(http.StatusForbidden)
	default:
		details = reason
	}

	// create a http response writer recorder
	w := httptest.NewRecorder()
	r := getHTTPRequestFromCheckRequest(in)

	// build the user info / debug endpoint
	debugEndpoint, _ := a.userInfoEndpointURL(in) // if there's an error, we just wont display it

	// run the request through our go error handler
	httpErr := httputil.HTTPError{
		Status:    int(code),
		Err:       errors.New(details),
		DebugURL:  debugEndpoint,
		RequestID: requestid.FromContext(ctx),
	}
	httpErr.ErrorResponse(w, r)

	// transpose the go http response writer into a envoy response
	resp := w.Result()
	defer resp.Body.Close()
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Error(ctx).Err(err).Msg("error executing error template")
		return nil, err
	}
	// convert go headers to envoy headers
	respHeader := toEnvoyHeaders(resp.Header)

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

func (a *Authorize) redirectResponse(ctx context.Context, in *envoy_service_auth_v3.CheckRequest) (*envoy_service_auth_v3.CheckResponse, error) {
	opts := a.currentOptions.Load()
	state := a.state.Load()
	authenticateURL, err := opts.GetAuthenticateURL()
	if err != nil {
		return nil, err
	}

	signinURL := authenticateURL.ResolveReference(&url.URL{
		Path: "/.pomerium/sign_in",
	})
	q := signinURL.Query()

	// always assume https scheme
	url := getCheckRequestURL(in)
	url.Scheme = "https"

	q.Set(urlutil.QueryRedirectURI, url.String())
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
