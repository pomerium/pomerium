package authorize

import (
	"bytes"
	"net/http"
	"net/url"
	"strings"

	envoy_api_v2_core "github.com/envoyproxy/go-control-plane/envoy/api/v2/core"
	envoy_service_auth_v2 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v2"
	envoy_type "github.com/envoyproxy/go-control-plane/envoy/type"
	"google.golang.org/genproto/googleapis/rpc/status"
	"google.golang.org/grpc/codes"

	"github.com/pomerium/pomerium/internal/grpc/authorize"
	"github.com/pomerium/pomerium/internal/httputil"
	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/internal/urlutil"
)

func (a *Authorize) okResponse(
	reply *authorize.IsAuthorizedReply,
	rawSession []byte,
	isNewSession bool,
) *envoy_service_auth_v2.CheckResponse {

	requestHeaders, err := a.getEnvoyRequestHeaders(rawSession, isNewSession)
	if err != nil {
		log.Warn().Err(err).Msg("authorize: error generating new request headers")
	}
	requestHeaders = append(requestHeaders,
		mkHeader(httputil.HeaderPomeriumJWTAssertion, reply.SignedJwt))

	return &envoy_service_auth_v2.CheckResponse{
		Status: &status.Status{Code: int32(codes.OK), Message: "OK"},
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
) *envoy_service_auth_v2.CheckResponse {

	returnHTMLError := true
	inHeaders := in.GetAttributes().GetRequest().GetHttp().GetHeaders()
	if inHeaders != nil {
		returnHTMLError = strings.Contains(inHeaders["accept"], "text/html")
	}

	if returnHTMLError {
		return a.htmlDeniedResponse(code, reason, headers)
	}
	return a.plainTextDeniedResponse(code, reason, headers)
}

func (a *Authorize) htmlDeniedResponse(code int32, reason string, headers map[string]string) *envoy_service_auth_v2.CheckResponse {
	var details string
	switch code {
	case httputil.StatusInvalidClientCertificate:
		details = "a valid client certificate is required to access this page"
	case http.StatusForbidden:
		details = "access to this page is forbidden"
	default:
		details = reason
	}

	var buf bytes.Buffer
	err := a.templates.ExecuteTemplate(&buf, "error.html", map[string]interface{}{
		"Status":     code,
		"StatusText": reason,
		"CanDebug":   code/100 == 4,
		"Error":      details,
	})
	if err != nil {
		buf.WriteString(reason)
		log.Error().Err(err).Msg("error executing error template")
	}

	envoyHeaders := []*envoy_api_v2_core.HeaderValueOption{
		mkHeader("Content-Type", "text/html"),
	}
	for k, v := range headers {
		envoyHeaders = append(envoyHeaders, mkHeader(k, v))
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
	}
}

func (a *Authorize) plainTextDeniedResponse(code int32, reason string, headers map[string]string) *envoy_service_auth_v2.CheckResponse {
	envoyHeaders := []*envoy_api_v2_core.HeaderValueOption{
		mkHeader("Content-Type", "text/plain"),
	}
	for k, v := range headers {
		envoyHeaders = append(envoyHeaders, mkHeader(k, v))
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

func (a *Authorize) redirectResponse(in *envoy_service_auth_v2.CheckRequest) *envoy_service_auth_v2.CheckResponse {
	opts := a.currentOptions.Load()

	signinURL := opts.AuthenticateURL.ResolveReference(&url.URL{Path: "/.pomerium/sign_in"})
	q := signinURL.Query()
	q.Set(urlutil.QueryRedirectURI, getCheckRequestURL(in).String())
	signinURL.RawQuery = q.Encode()
	redirectTo := urlutil.NewSignedURL(opts.SharedKey, signinURL).String()

	return a.deniedResponse(in, http.StatusFound, "Login", map[string]string{
		"Location": redirectTo,
	})
}

func mkHeader(k, v string) *envoy_api_v2_core.HeaderValueOption {
	return &envoy_api_v2_core.HeaderValueOption{
		Header: &envoy_api_v2_core.HeaderValue{
			Key:   k,
			Value: v,
		},
	}
}
