package authorize

import (
	"context"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"

	"github.com/pomerium/pomerium/authorize/evaluator"
	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/httputil"
	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/internal/sessions"
	"github.com/pomerium/pomerium/internal/telemetry/requestid"
	"github.com/pomerium/pomerium/internal/telemetry/trace"
	"github.com/pomerium/pomerium/internal/urlutil"

	envoy_api_v2_core "github.com/envoyproxy/go-control-plane/envoy/api/v2/core"
	envoy_service_auth_v2 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v2"
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
	hreq := getHTTPRequestFromCheckRequest(in)

	hdrs := getCheckRequestHeaders(in)

	isNewSession := false
	sess, sesserr := loadSession(hreq, a.currentOptions.Load(), a.currentEncoder.Load())
	if a.isExpired(sess) {
		log.Info().Msg("refreshing session")
		if newSession, err := a.refreshSession(ctx, sess); err == nil {
			sess = newSession
			sesserr = nil
			isNewSession = true
		} else {
			log.Warn().Err(err).Msg("authorize: error refreshing session")
		}
	}

	requestHeaders, err := a.getEnvoyRequestHeaders(sess, isNewSession)
	if err != nil {
		log.Warn().Err(err).Msg("authorize: error generating new request headers")
	}

	requestURL := getCheckRequestURL(in)
	req := &evaluator.Request{
		User:              string(sess),
		Header:            hdrs,
		Host:              hattrs.GetHost(),
		Method:            hattrs.GetMethod(),
		RequestURI:        requestURL.String(),
		RemoteAddr:        in.GetAttributes().GetSource().GetAddress().String(),
		URL:               requestURL.String(),
		ClientCertificate: getPeerCertificate(in),
	}
	reply, err := a.pe.IsAuthorized(ctx, req)
	if err != nil {
		return nil, err
	}

	evt := log.Info().Str("service", "authorize")
	// request
	evt = evt.Str("request-id", requestid.FromContext(ctx))
	evt = evt.Strs("check-request-id", hdrs["X-Request-Id"])
	evt = evt.Str("method", hattrs.GetMethod())
	evt = evt.Interface("headers", hdrs)
	evt = evt.Str("path", hattrs.GetPath())
	evt = evt.Str("host", hattrs.GetHost())
	evt = evt.Str("query", hattrs.GetQuery())
	// reply
	evt = evt.Bool("allow", reply.GetAllow())
	evt = evt.Bool("session-expired", reply.GetSessionExpired())
	evt = evt.Strs("deny-reasons", reply.GetDenyReasons())
	evt = evt.Str("email", reply.GetEmail())
	evt = evt.Strs("groups", reply.GetGroups())
	evt = evt.Str("session", string(sess))
	if reply.GetHttpStatus() != nil {
		evt = evt.Interface("http_status", reply.GetHttpStatus())
	}
	evt.Msg("authorize check")

	requestHeaders = append(requestHeaders,
		&envoy_api_v2_core.HeaderValueOption{
			Header: &envoy_api_v2_core.HeaderValue{
				Key:   "x-pomerium-jwt-assertion",
				Value: reply.SignedJwt,
			},
		})

	if reply.GetHttpStatus().GetCode() > 0 && reply.GetHttpStatus().GetCode() != http.StatusOK {
		return a.deniedResponse(in,
			reply.GetHttpStatus().GetCode(),
			reply.GetHttpStatus().GetMessage(),
			reply.GetHttpStatus().GetHeaders(),
		), nil
	}

	if reply.Allow {
		return &envoy_service_auth_v2.CheckResponse{
			Status: &status.Status{Code: int32(codes.OK), Message: "OK"},
			HttpResponse: &envoy_service_auth_v2.CheckResponse_OkResponse{
				OkResponse: &envoy_service_auth_v2.OkHttpResponse{
					Headers: requestHeaders,
				},
			},
		}, nil
	}

	if reply.SessionExpired {
		sesserr = sessions.ErrExpired
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
		return a.deniedResponse(in, http.StatusForbidden, msg, nil), nil
	}

	// no redirect for forward auth, that's handled by a separate config setting
	if isForwardAuth {
		return a.deniedResponse(in, http.StatusUnauthorized, "Unauthenticated", nil), nil
	}

	signinURL := opts.AuthenticateURL.ResolveReference(&url.URL{Path: "/.pomerium/sign_in"})
	q := signinURL.Query()
	q.Set(urlutil.QueryRedirectURI, requestURL.String())
	signinURL.RawQuery = q.Encode()
	redirectTo := urlutil.NewSignedURL(opts.SharedKey, signinURL).String()

	return a.deniedResponse(in, http.StatusFound, "Login", map[string]string{
		"Location": redirectTo,
	}), nil
}

func (a *Authorize) getEnvoyRequestHeaders(rawjwt []byte, isNewSession bool) ([]*envoy_api_v2_core.HeaderValueOption, error) {
	var hvos []*envoy_api_v2_core.HeaderValueOption

	if isNewSession {
		cookieStore, err := getCookieStore(a.currentOptions.Load(), a.currentEncoder.Load())
		if err != nil {
			return nil, err
		}

		hdrs, err := getJWTSetCookieHeaders(cookieStore, rawjwt)
		if err != nil {
			return nil, err
		}
		for k, v := range hdrs {
			hvos = append(hvos, &envoy_api_v2_core.HeaderValueOption{
				Header: &envoy_api_v2_core.HeaderValue{
					Key:   "x-pomerium-" + k,
					Value: v,
				},
			})
		}
	}

	hdrs, err := getJWTClaimHeaders(a.currentOptions.Load(), a.currentEncoder.Load(), rawjwt)
	if err != nil {
		return nil, err
	}
	for k, v := range hdrs {
		hvos = append(hvos, &envoy_api_v2_core.HeaderValueOption{
			Header: &envoy_api_v2_core.HeaderValue{
				Key:   k,
				Value: v,
			},
		})
	}

	return hvos, nil
}

func (a *Authorize) refreshSession(ctx context.Context, rawSession []byte) (newSession []byte, err error) {
	options := a.currentOptions.Load()
	encoder := a.currentEncoder.Load()

	var state sessions.State
	if err := encoder.Unmarshal(rawSession, &state); err != nil {
		return nil, fmt.Errorf("error unmarshaling raw session: %w", err)
	}

	// 1 - build a signed url to call refresh on authenticate service
	refreshURI := options.AuthenticateURL.ResolveReference(&url.URL{Path: "/.pomerium/refresh"})
	signedRefreshURL := urlutil.NewSignedURL(options.SharedKey, refreshURI).String()

	// 2 - http call to authenticate service
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, signedRefreshURL, nil)
	if err != nil {
		return nil, fmt.Errorf("authorize: refresh request: %w", err)
	}
	req.Header.Set("Authorization", fmt.Sprintf("Pomerium %s", rawSession))
	req.Header.Set("X-Requested-With", "XmlHttpRequest")
	req.Header.Set("Accept", "application/json")

	res, err := httputil.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("authorize: client err %s: %w", signedRefreshURL, err)
	}
	defer res.Body.Close()
	newJwt, err := ioutil.ReadAll(io.LimitReader(res.Body, 4<<10))
	if err != nil {
		return nil, err
	}
	// auth couldn't refresh the session, delete the session and reload via 302
	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("authorize: backend refresh failed: %s", newJwt)
	}
	return newJwt, nil
}

func (a *Authorize) isExpired(rawSession []byte) bool {
	state := sessions.State{}
	err := a.currentEncoder.Load().Unmarshal(rawSession, &state)
	return err == nil && state.IsExpired()
}

func getHTTPRequestFromCheckRequest(req *envoy_service_auth_v2.CheckRequest) *http.Request {
	hattrs := req.GetAttributes().GetRequest().GetHttp()
	return &http.Request{
		Method:     hattrs.GetMethod(),
		URL:        getCheckRequestURL(req),
		Header:     getCheckRequestHeaders(req),
		Body:       ioutil.NopCloser(strings.NewReader(hattrs.GetBody())),
		Host:       hattrs.GetHost(),
		RequestURI: hattrs.GetPath(),
	}
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

// getPeerCertificate gets the PEM-encoded peer certificate from the check request
func getPeerCertificate(in *envoy_service_auth_v2.CheckRequest) string {
	// ignore the error as we will just return the empty string in that case
	cert, _ := url.QueryUnescape(in.GetAttributes().GetSource().GetCertificate())
	return cert
}
