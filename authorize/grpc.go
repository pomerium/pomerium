package authorize

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"

	"github.com/pomerium/pomerium/authorize/evaluator"
	"github.com/pomerium/pomerium/internal/grpc/authorize"
	"github.com/pomerium/pomerium/internal/httputil"
	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/internal/sessions"
	"github.com/pomerium/pomerium/internal/telemetry/requestid"
	"github.com/pomerium/pomerium/internal/telemetry/trace"
	"github.com/pomerium/pomerium/internal/urlutil"

	envoy_api_v2_core "github.com/envoyproxy/go-control-plane/envoy/api/v2/core"
	envoy_service_auth_v2 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v2"
)

// Check implements the envoy auth server gRPC endpoint.
func (a *Authorize) Check(ctx context.Context, in *envoy_service_auth_v2.CheckRequest) (*envoy_service_auth_v2.CheckResponse, error) {
	ctx, span := trace.StartSpan(ctx, "authorize.grpc.Check")
	defer span.End()

	// maybe rewrite http request for forward auth
	isForwardAuth := a.handleForwardAuth(in)
	hreq := getHTTPRequestFromCheckRequest(in)

	isNewSession := false
	rawJWT, sessionErr := loadSession(hreq, a.currentOptions.Load(), a.currentEncoder.Load())
	if a.isExpired(rawJWT) {
		log.Info().Msg("refreshing session")
		if newRawJWT, err := a.refreshSession(ctx, rawJWT); err == nil {
			rawJWT = newRawJWT
			sessionErr = nil
			isNewSession = true
		} else {
			log.Warn().Err(err).Msg("authorize: error refreshing session")
			// set the error to expired so that we can force a new login
			sessionErr = sessions.ErrExpired
		}
	}

	req := getEvaluatorRequestFromCheckRequest(in, rawJWT)
	reply, err := a.pe.IsAuthorized(ctx, req)
	if err != nil {
		return nil, err
	}
	logAuthorizeCheck(ctx, in, reply, rawJWT)

	switch {
	case reply.GetHttpStatus().GetCode() > 0 && reply.GetHttpStatus().GetCode() != http.StatusOK:
		// custom error from the IsAuthorized call
		return a.deniedResponse(in,
			reply.GetHttpStatus().GetCode(),
			reply.GetHttpStatus().GetMessage(),
			reply.GetHttpStatus().GetHeaders(),
		), nil

	case reply.Allow:
		// ok!
		return a.okResponse(reply, rawJWT, isNewSession), nil

	case reply.SessionExpired,
		errors.Is(sessionErr, sessions.ErrExpired),
		errors.Is(sessionErr, sessions.ErrIssuedInTheFuture),
		errors.Is(sessionErr, sessions.ErrMalformed),
		errors.Is(sessionErr, sessions.ErrNoSessionFound),
		errors.Is(sessionErr, sessions.ErrNotValidYet):
		// redirect to login

		// no redirect for forward auth, that's handled by a separate config setting
		if isForwardAuth {
			return a.deniedResponse(in, http.StatusUnauthorized, "Unauthenticated", nil), nil
		}

		return a.redirectResponse(in), nil

	default:
		// all other errors
		var msg string
		if sessionErr != nil {
			msg = sessionErr.Error()
		}
		return a.deniedResponse(in, http.StatusForbidden, msg, nil), nil
	}
}

func (a *Authorize) getEnvoyRequestHeaders(rawJWT []byte, isNewSession bool) ([]*envoy_api_v2_core.HeaderValueOption, error) {
	var hvos []*envoy_api_v2_core.HeaderValueOption

	if isNewSession {
		cookieStore, err := getCookieStore(a.currentOptions.Load(), a.currentEncoder.Load())
		if err != nil {
			return nil, err
		}

		hdrs, err := getJWTSetCookieHeaders(cookieStore, rawJWT)
		if err != nil {
			return nil, err
		}
		for k, v := range hdrs {
			hvos = append(hvos, mkHeader("x-pomerium-"+k, v))
		}
	}

	hdrs, err := getJWTClaimHeaders(a.currentOptions.Load(), a.currentEncoder.Load(), rawJWT)
	if err != nil {
		return nil, err
	}
	for k, v := range hdrs {
		hvos = append(hvos, mkHeader(k, v))
	}

	return hvos, nil
}

func (a *Authorize) refreshSession(ctx context.Context, rawJWT []byte) (newSession []byte, err error) {
	options := a.currentOptions.Load()

	// 1 - build a signed url to call refresh on authenticate service
	refreshURI := options.GetAuthenticateURL().ResolveReference(&url.URL{Path: "/.pomerium/refresh"})
	signedRefreshURL := urlutil.NewSignedURL(options.SharedKey, refreshURI).String()

	// 2 - http call to authenticate service
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, signedRefreshURL, nil)
	if err != nil {
		return nil, fmt.Errorf("authorize: refresh request: %w", err)
	}
	req.Header.Set("Authorization", fmt.Sprintf("Pomerium %s", rawJWT))
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

func (a *Authorize) handleForwardAuth(req *envoy_service_auth_v2.CheckRequest) bool {
	opts := a.currentOptions.Load()

	if opts.ForwardAuthURL == nil {
		return false
	}

	checkURL := getCheckRequestURL(req)
	if urlutil.StripPort(checkURL.Host) == urlutil.StripPort(opts.GetForwardAuthURL().Host) {
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

func getEvaluatorRequestFromCheckRequest(in *envoy_service_auth_v2.CheckRequest, rawJWT []byte) *evaluator.Request {
	requestURL := getCheckRequestURL(in)
	req := &evaluator.Request{
		User:              string(rawJWT),
		Header:            getCheckRequestHeaders(in),
		Host:              in.GetAttributes().GetRequest().GetHttp().GetHost(),
		Method:            in.GetAttributes().GetRequest().GetHttp().GetMethod(),
		RequestURI:        requestURL.String(),
		URL:               requestURL.String(),
		ClientCertificate: getPeerCertificate(in),
	}
	return req
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

	if h.GetHeaders() != nil {
		if fwdProto, ok := h.GetHeaders()["x-forwarded-proto"]; ok {
			u.Scheme = fwdProto
		}
	}
	return u
}

// getPeerCertificate gets the PEM-encoded peer certificate from the check request
func getPeerCertificate(in *envoy_service_auth_v2.CheckRequest) string {
	// ignore the error as we will just return the empty string in that case
	cert, _ := url.QueryUnescape(in.GetAttributes().GetSource().GetCertificate())
	return cert
}

func logAuthorizeCheck(
	ctx context.Context,
	in *envoy_service_auth_v2.CheckRequest,
	reply *authorize.IsAuthorizedReply,
	rawJWT []byte,
) {
	hdrs := getCheckRequestHeaders(in)
	hattrs := in.GetAttributes().GetRequest().GetHttp()
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
	if rawJWT != nil {
		evt = evt.Str("session", string(rawJWT))
	}
	if reply.GetHttpStatus() != nil {
		evt = evt.Interface("http_status", reply.GetHttpStatus())
	}
	evt.Msg("authorize check")
}
