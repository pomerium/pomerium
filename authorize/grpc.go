package authorize

import (
	"context"
	"net/http"
	"net/url"
	"strings"

	"github.com/pomerium/pomerium/authorize/evaluator"
	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/encoding/jws"
	"github.com/pomerium/pomerium/internal/grpc/authorize"
	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/internal/sessions"
	"github.com/pomerium/pomerium/internal/sessions/cookie"
	"github.com/pomerium/pomerium/internal/telemetry/trace"
	"github.com/pomerium/pomerium/internal/urlutil"

	envoy_api_v2_core "github.com/envoyproxy/go-control-plane/envoy/api/v2/core"
	envoy_service_auth_v2 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v2"
	envoy_type "github.com/envoyproxy/go-control-plane/envoy/type"
	"google.golang.org/genproto/googleapis/rpc/status"
	"google.golang.org/grpc/codes"
)

// Check implements the envoy auth server gRPC endpoint.
func (a *Authorize) Check(ctx context.Context, in *envoy_service_auth_v2.CheckRequest) (*envoy_service_auth_v2.CheckResponse, error) {
	ctx, span := trace.StartSpan(ctx, "authorize.grpc.Check")
	defer span.End()

	opts := a.currentOptions.Load()

	// maybe rewrite http request for forward auth
	isForwardAuth := handleForwardAuth(opts, in)

	hattrs := in.GetAttributes().GetRequest().GetHttp()

	hdrs := getCheckRequestHeaders(in)
	sess, sesserr := a.loadSessionFromCheckRequest(in)
	requestURL := getCheckRequestURL(in)
	req := &evaluator.Request{
		User:       sess,
		Header:     hdrs,
		Host:       hattrs.GetHost(),
		Method:     hattrs.GetMethod(),
		RequestURI: requestURL.String(),
		RemoteAddr: in.GetAttributes().GetSource().GetAddress().String(),
		URL:        requestURL.String(),
	}
	reply, err := a.pe.IsAuthorized(ctx, req)
	if err != nil {
		return nil, err
	}

	evt := log.Info().Str("service", "authorize")
	// request
	evt = evt.Str("request-id", hattrs.GetId())
	evt = evt.Str("method", hattrs.GetMethod())
	evt = evt.Str("path", hattrs.GetPath())
	evt = evt.Str("host", hattrs.GetHost())
	evt = evt.Str("query", hattrs.GetQuery())
	// reply
	evt = evt.Bool("allow", reply.GetAllow())
	evt = evt.Bool("session-expired", reply.GetSessionExpired())
	evt = evt.Strs("deny-reasons", reply.GetDenyReasons())
	evt = evt.Str("email", reply.GetEmail())
	evt = evt.Strs("groups", reply.GetGroups())
	evt.Msg("authorize check")

	if reply.Allow {
		return &envoy_service_auth_v2.CheckResponse{
			Status:       &status.Status{Code: int32(codes.OK), Message: "OK"},
			HttpResponse: &envoy_service_auth_v2.CheckResponse_OkResponse{OkResponse: &envoy_service_auth_v2.OkHttpResponse{}},
		}, nil
	}

	switch sesserr {
	case sessions.ErrExpired, sessions.ErrIssuedInTheFuture, sessions.ErrMalformed, sessions.ErrNoSessionFound, sessions.ErrNotValidYet:
		// redirect to login
	default:
		var msg string
		if sesserr != nil {
			msg = sesserr.Error()
		}
		// all other errors
		return &envoy_service_auth_v2.CheckResponse{
			Status: &status.Status{Code: int32(codes.PermissionDenied), Message: msg},
			HttpResponse: &envoy_service_auth_v2.CheckResponse_DeniedResponse{
				DeniedResponse: &envoy_service_auth_v2.DeniedHttpResponse{
					Status: &envoy_type.HttpStatus{
						Code: envoy_type.StatusCode_Forbidden,
					},
				},
			},
		}, nil
	}

	// no redirect for forward auth, that's handled by a separate config setting
	if isForwardAuth {
		return &envoy_service_auth_v2.CheckResponse{
			Status: &status.Status{Code: int32(codes.Unauthenticated)},
			HttpResponse: &envoy_service_auth_v2.CheckResponse_DeniedResponse{
				DeniedResponse: &envoy_service_auth_v2.DeniedHttpResponse{
					Status: &envoy_type.HttpStatus{
						Code: envoy_type.StatusCode_Unauthorized,
					},
				},
			},
		}, nil
	}

	signinURL := opts.AuthenticateURL.ResolveReference(&url.URL{Path: "/.pomerium/sign_in"})
	q := signinURL.Query()
	q.Set(urlutil.QueryRedirectURI, requestURL.String())
	signinURL.RawQuery = q.Encode()
	redirectTo := urlutil.NewSignedURL(opts.SharedKey, signinURL).String()

	return &envoy_service_auth_v2.CheckResponse{
		Status: &status.Status{
			Code:    int32(codes.Unauthenticated),
			Message: "unauthenticated",
		},
		HttpResponse: &envoy_service_auth_v2.CheckResponse_DeniedResponse{
			DeniedResponse: &envoy_service_auth_v2.DeniedHttpResponse{
				Status: &envoy_type.HttpStatus{
					Code: envoy_type.StatusCode_Found,
				},
				Headers: []*envoy_api_v2_core.HeaderValueOption{{
					Header: &envoy_api_v2_core.HeaderValue{
						Key:   "Location",
						Value: redirectTo,
					},
				}},
			},
		},
	}, nil
}

func (a *Authorize) loadSessionFromCheckRequest(req *envoy_service_auth_v2.CheckRequest) (string, error) {
	opts := a.currentOptions.Load()

	// used to load and verify JWT tokens signed by the authenticate service
	encoder, err := jws.NewHS256Signer([]byte(opts.SharedKey), opts.AuthenticateURL.Host)
	if err != nil {
		return "", err
	}

	cookieOptions := &cookie.Options{
		Name:     opts.CookieName,
		Domain:   opts.CookieDomain,
		Secure:   opts.CookieSecure,
		HTTPOnly: opts.CookieHTTPOnly,
		Expire:   opts.CookieExpire,
	}

	cookieStore, err := cookie.NewStore(cookieOptions, encoder)
	if err != nil {
		return "", err
	}

	sess, err := cookieStore.LoadSession(&http.Request{
		Header: http.Header(getCheckRequestHeaders(req)),
	})
	return sess, err
}

type protoHeader map[string]*authorize.IsAuthorizedRequest_Headers

func cloneHeaders(in protoHeader) map[string][]string {
	out := make(map[string][]string, len(in))
	for key, values := range in {
		newValues := make([]string, len(values.Value))
		copy(newValues, values.Value)
		out[key] = newValues
	}
	return out
}

func getFullURL(rawurl, host string) string {
	u, err := url.Parse(rawurl)
	if err != nil {
		u = &url.URL{Path: rawurl}
	}
	if u.Host == "" {
		u.Host = host
	}
	if u.Scheme == "" {
		u.Scheme = "http"
	}
	return u.String()
}

func getCheckRequestHeaders(req *envoy_service_auth_v2.CheckRequest) map[string][]string {
	h := make(map[string][]string)
	ch := req.GetAttributes().GetRequest().GetHttp().GetHeaders()
	for k, v := range ch {
		h[http.CanonicalHeaderKey(k)] = []string{v}
	}
	return h
}

func getCheckRequestURL(req *envoy_service_auth_v2.CheckRequest) *url.URL {
	h := req.GetAttributes().GetRequest().GetHttp()
	u := &url.URL{
		Scheme: h.GetScheme(),
		Host:   h.GetHost(),
	}

	// envoy sends the query string as part of the path
	path := h.GetPath()
	if idx := strings.Index(path, "?"); idx != -1 {
		u.Path, u.RawQuery = path[:idx], path[idx+1:]
	} else {
		u.Path = path
	}

	if h.Headers != nil {
		if fwdProto, ok := h.Headers["x-forwarded-proto"]; ok {
			u.Scheme = fwdProto
		}
	}
	return u
}

func handleForwardAuth(opts config.Options, req *envoy_service_auth_v2.CheckRequest) bool {
	if opts.ForwardAuthURL == nil {
		return false
	}

	checkURL := getCheckRequestURL(req)
	if urlutil.StripPort(checkURL.Host) == urlutil.StripPort(opts.ForwardAuthURL.Host) {
		if (checkURL.Path == "/" || checkURL.Path == "/verify") && checkURL.Query().Get("uri") != "" {
			verifyURL, err := url.Parse(checkURL.Query().Get("uri"))
			if err != nil {
				log.Warn().Str("uri", checkURL.Query().Get("uri")).Err(err).Msg("failed to parse uri for forward authentication")
				return false
			}
			req.Attributes.Request.Http.Scheme = verifyURL.Scheme
			req.Attributes.Request.Http.Host = verifyURL.Host
			req.Attributes.Request.Http.Path = verifyURL.Path
			// envoy sends the query string as part of the path
			if verifyURL.RawQuery != "" {
				req.Attributes.Request.Http.Path += "?" + verifyURL.RawQuery
			}
			return true
		}
	}

	return false
}
