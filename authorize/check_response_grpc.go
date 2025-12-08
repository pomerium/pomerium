package authorize

import (
	"net/http"
	"strconv"
	"strings"

	envoy_service_auth_v3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	"google.golang.org/grpc/codes"
)

func isGRPCRequest(in *envoy_service_auth_v3.CheckRequest) bool {
	hdrs := in.GetAttributes().GetRequest().GetHttp().GetHeaders()
	if hdrs == nil {
		return false
	}
	return hdrs["content-type"] == "application/grpc" || strings.HasPrefix(hdrs["content-type"], "application/grpc+")
}

func isGRPCWebRequest(in *envoy_service_auth_v3.CheckRequest) bool {
	hdrs := in.GetAttributes().GetRequest().GetHttp().GetHeaders()
	if hdrs == nil {
		return false
	}
	return hdrs["content-type"] == "application/grpc-web-text" || strings.HasPrefix(hdrs["content-type"], "application/grpc-web+")
}

func deniedResponseForGRPC(
	code int32, reason string, headers http.Header,
) *envoy_service_auth_v3.CheckResponse {
	headers.Set("Content-Type", "application/grpc+json")
	headers["grpc-status"] = []string{strconv.Itoa(int(httpStatusCodeToGRPCStatusCode(code)))}
	headers["grpc-message"] = []string{reason}
	return mkDeniedCheckResponse(code, headers, "")
}

func deniedResponseForGRPCWeb(
	code int32, reason string, headers http.Header,
) *envoy_service_auth_v3.CheckResponse {
	headers.Set("Content-Type", "application/grpc-web+json")
	headers["grpc-status"] = []string{strconv.Itoa(int(httpStatusCodeToGRPCStatusCode(code)))}
	headers["grpc-message"] = []string{reason}
	return mkDeniedCheckResponse(code, headers, "")
}

func httpStatusCodeToGRPCStatusCode(httpStatusCode int32) codes.Code {
	// from https://github.com/grpc/grpc/blob/master/doc/http-grpc-status-mapping.md
	switch httpStatusCode {
	case http.StatusBadRequest:
		return codes.Internal
	case http.StatusUnauthorized:
		return codes.Unauthenticated
	case http.StatusForbidden:
		return codes.PermissionDenied
	case http.StatusNotFound:
		return codes.Unimplemented
	case http.StatusTooManyRequests,
		http.StatusBadGateway,
		http.StatusServiceUnavailable,
		http.StatusGatewayTimeout:
		return codes.Unavailable
	default:
		return codes.Unknown
	}
}
