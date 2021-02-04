package authorize

import (
	"bytes"
	"net/http"
	"net/url"
	"sort"
	"strings"

	envoy_api_v2_core "github.com/envoyproxy/go-control-plane/envoy/api/v2/core"
	envoy_service_auth_v2 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v2"
	envoy_type "github.com/envoyproxy/go-control-plane/envoy/type"
	"github.com/golang/protobuf/ptypes/wrappers"
	"google.golang.org/genproto/googleapis/rpc/status"
	"google.golang.org/grpc/codes"

	"github.com/pomerium/pomerium/authorize/evaluator"
	"github.com/pomerium/pomerium/internal/httputil"
	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/internal/urlutil"
)

func (a *Authorize) okResponse(reply *evaluator.Result) *envoy_service_auth_v2.CheckResponse {
	var requestHeaders []*envoy_api_v2_core.HeaderValueOption
	for k, v := range reply.Headers {
		requestHeaders = append(requestHeaders, mkHeader(k, v, false))
	}
	sort.Slice(requestHeaders, func(i, j int) bool {
		return requestHeaders[i].Header.Key < requestHeaders[j].Header.Value
	})
	return &envoy_service_auth_v2.CheckResponse{
		Status: &status.Status{Code: int32(codes.OK), Message: reply.Message},
		HttpResponse: &envoy_service_auth_v2.CheckResponse_OkResponse{
			OkResponse: &envoy_service_auth_v2.OkHttpResponse{
				Headers: requestHeaders,
			},
		},
	}
}

func (a *Authorize) deniedResponse(
	in *envoy_service_auth_v2.CheckRequest,
	code int32, reason string, headers map[string]string,
) (*envoy_service_auth_v2.CheckResponse, error) {
	returnHTMLError := true
	inHeaders := in.GetAttributes().GetRequest().GetHttp().GetHeaders()
	if inHeaders != nil {
		returnHTMLError = strings.Contains(inHeaders["accept"], "text/html")
	}

	if returnHTMLError {
		return a.htmlDeniedResponse(in, code, reason, headers)
	}
	return a.plainTextDeniedResponse(code, reason, headers), nil
}

func (a *Authorize) htmlDeniedResponse(
	in *envoy_service_auth_v2.CheckRequest,
	code int32, reason string, headers map[string]string,
) (*envoy_service_auth_v2.CheckResponse, error) {
	opts := a.currentOptions.Load()
	authenticateURL, err := opts.GetAuthenticateURL()
	if err != nil {
		return nil, err
	}
	debugEndpoint := authenticateURL.ResolveReference(&url.URL{Path: "/.pomerium/"})

	// create go-style http request
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

	var details string
	switch code {
	case httputil.StatusInvalidClientCertificate:
		details = "a valid client certificate is required to access this page"
	case http.StatusForbidden:
		details = "access to this page is forbidden"
	default:
		details = reason
	}

	if reason == "" {
		reason = http.StatusText(int(code))
	}

	var buf bytes.Buffer
	err = a.templates.ExecuteTemplate(&buf, "error.html", map[string]interface{}{
		"Status":     code,
		"StatusText": reason,
		"CanDebug":   code/100 == 4,
		"DebugURL":   debugEndpoint,
		"Error":      details,
	})
	if err != nil {
		buf.WriteString(reason)
		log.Error().Err(err).Msg("error executing error template")
	}

	envoyHeaders := []*envoy_api_v2_core.HeaderValueOption{
		mkHeader("Content-Type", "text/html", false),
	}
	for k, v := range headers {
		envoyHeaders = append(envoyHeaders, mkHeader(k, v, false))
	}

	return &envoy_service_auth_v2.CheckResponse{
		Status: &status.Status{Code: int32(codes.PermissionDenied), Message: "Access Denied"},
		HttpResponse: &envoy_service_auth_v2.CheckResponse_DeniedResponse{
			DeniedResponse: &envoy_service_auth_v2.DeniedHttpResponse{
				Status: &envoy_type.HttpStatus{
					Code: envoy_type.StatusCode(code),
				},
				Headers: envoyHeaders,
				Body:    buf.String(),
			},
		},
	}, nil
}

func (a *Authorize) plainTextDeniedResponse(code int32, reason string, headers map[string]string) *envoy_service_auth_v2.CheckResponse {
	envoyHeaders := []*envoy_api_v2_core.HeaderValueOption{
		mkHeader("Content-Type", "text/plain", false),
	}
	for k, v := range headers {
		envoyHeaders = append(envoyHeaders, mkHeader(k, v, false))
	}

	return &envoy_service_auth_v2.CheckResponse{
		Status: &status.Status{Code: int32(codes.PermissionDenied), Message: "Access Denied"},
		HttpResponse: &envoy_service_auth_v2.CheckResponse_DeniedResponse{
			DeniedResponse: &envoy_service_auth_v2.DeniedHttpResponse{
				Status: &envoy_type.HttpStatus{
					Code: envoy_type.StatusCode(code),
				},
				Headers: envoyHeaders,
				Body:    reason,
			},
		},
	}
}

func (a *Authorize) redirectResponse(in *envoy_service_auth_v2.CheckRequest) (*envoy_service_auth_v2.CheckResponse, error) {
	opts := a.currentOptions.Load()
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
	redirectTo := urlutil.NewSignedURL(opts.SharedKey, signinURL).String()

	return a.deniedResponse(in, http.StatusFound, "Login", map[string]string{
		"Location": redirectTo,
	})
}

func mkHeader(k, v string, shouldAppend bool) *envoy_api_v2_core.HeaderValueOption {
	return &envoy_api_v2_core.HeaderValueOption{
		Header: &envoy_api_v2_core.HeaderValue{
			Key:   k,
			Value: v,
		},
		Append: &wrappers.BoolValue{
			Value: shouldAppend,
		},
	}
}
