package authorize

import (
	"context"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/golang/protobuf/ptypes"
	"github.com/google/uuid"

	"github.com/pomerium/pomerium/authorize/evaluator"
	"github.com/pomerium/pomerium/internal/grpc/session"
	"github.com/pomerium/pomerium/internal/grpc/user"
	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/internal/sessions"
	"github.com/pomerium/pomerium/internal/telemetry/requestid"
	"github.com/pomerium/pomerium/internal/telemetry/trace"
	"github.com/pomerium/pomerium/internal/urlutil"

	envoy_api_v2_core "github.com/envoyproxy/go-control-plane/envoy/api/v2/core"
	envoy_service_auth_v2 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v2"
)

var sessionTypeURL, userTypeURL string

func init() {
	any, _ := ptypes.MarshalAny(new(session.Session))
	sessionTypeURL = any.GetTypeUrl()

	any, _ = ptypes.MarshalAny(new(user.User))
	userTypeURL = any.GetTypeUrl()
}

// Check implements the envoy auth server gRPC endpoint.
func (a *Authorize) Check(ctx context.Context, in *envoy_service_auth_v2.CheckRequest) (*envoy_service_auth_v2.CheckResponse, error) {
	ctx, span := trace.StartSpan(ctx, "authorize.grpc.Check")
	defer span.End()

	// maybe rewrite http request for forward auth
	isForwardAuth := a.handleForwardAuth(in)
	hreq := getHTTPRequestFromCheckRequest(in)
	rawJWT, _ := loadRawSession(hreq, a.currentOptions.Load(), a.currentEncoder.Load())
	sessionState, _ := loadSession(a.currentEncoder.Load(), rawJWT)

	if sessionState != nil {
		waitCtx, waitCancel := context.WithTimeout(ctx, time.Second*3)
		defer waitCancel()

		a.waitForSessionAndUser(waitCtx, sessionState.ID)
	}

	a.dataBrokerDataLock.RLock()
	defer a.dataBrokerDataLock.RUnlock()

	req := a.getEvaluatorRequestFromCheckRequest(in, sessionState)
	reply, err := a.pe.Evaluate(ctx, req)
	if err != nil {
		log.Error().Err(err).Msg("error during OPA evaluation")
		return nil, err
	}
	logAuthorizeCheck(ctx, in, reply)

	switch {
	case reply.Status == http.StatusOK:
		return a.okResponse(reply, rawJWT), nil
	case reply.Status == http.StatusUnauthorized:
		if isForwardAuth {
			return a.deniedResponse(in, http.StatusUnauthorized, "Unauthenticated", nil), nil
		}
		return a.redirectResponse(in), nil
	}
	return a.deniedResponse(in, int32(reply.Status), reply.Message, nil), nil
}

func (a *Authorize) waitForSessionAndUser(ctx context.Context, sessionID string) {
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()

	var userID string

	for {
		a.dataBrokerDataLock.RLock()
		s, ok := a.dataBrokerData.Get(sessionTypeURL, sessionID).(*session.Session)
		a.dataBrokerDataLock.RUnlock()

		if ok {
			if s.GetDeletedAt() != nil {
				return
			} else if s.GetUserId() != "" {
				userID = s.GetUserId()
				break
			} else {
				return
			}
		}

		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}

	for {
		a.dataBrokerDataLock.RLock()
		_, ok := a.dataBrokerData.Get(userTypeURL, userID).(*user.User)
		a.dataBrokerDataLock.RUnlock()

		if ok {
			return
		}

		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func (a *Authorize) getEnvoyRequestHeaders(rawJWT []byte) ([]*envoy_api_v2_core.HeaderValueOption, error) {
	var hvos []*envoy_api_v2_core.HeaderValueOption

	hdrs, err := getJWTClaimHeaders(a.currentOptions.Load(), a.currentEncoder.Load(), rawJWT)
	if err != nil {
		return nil, err
	}
	for k, v := range hdrs {
		hvos = append(hvos, mkHeader(k, v))
	}

	return hvos, nil
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

func (a *Authorize) getEvaluatorRequestFromCheckRequest(in *envoy_service_auth_v2.CheckRequest, sessionState *sessions.State) *evaluator.Request {
	requestURL := getCheckRequestURL(in)
	req := &evaluator.Request{
		DataBrokerData: a.dataBrokerData,
		HTTP: evaluator.RequestHTTP{
			Method:            in.GetAttributes().GetRequest().GetHttp().GetMethod(),
			URL:               requestURL.String(),
			Headers:           getCheckRequestHeaders(in),
			ClientCertificate: getPeerCertificate(in),
		},
	}
	if sessionState != nil {
		req.Session = evaluator.RequestSession{
			ID:                sessionState.ID,
			ImpersonateEmail:  sessionState.ImpersonateEmail,
			ImpersonateGroups: sessionState.ImpersonateGroups,
		}
		// if a user comes in with a session that has no id (jti), we will default it to a new UUID to prevent redirect loops.
		if req.Session.ID == "" {
			req.Session.ID = uuid.New().String()
		}
	}
	return req
}

func getHTTPRequestFromCheckRequest(req *envoy_service_auth_v2.CheckRequest) *http.Request {
	hattrs := req.GetAttributes().GetRequest().GetHttp()
	hreq := &http.Request{
		Method:     hattrs.GetMethod(),
		URL:        getCheckRequestURL(req),
		Header:     make(http.Header),
		Body:       ioutil.NopCloser(strings.NewReader(hattrs.GetBody())),
		Host:       hattrs.GetHost(),
		RequestURI: hattrs.GetPath(),
	}
	for k, v := range getCheckRequestHeaders(req) {
		hreq.Header.Set(k, v)
	}
	return hreq
}

func getCheckRequestHeaders(req *envoy_service_auth_v2.CheckRequest) map[string]string {
	hdrs := make(map[string]string)
	ch := req.GetAttributes().GetRequest().GetHttp().GetHeaders()
	for k, v := range ch {
		hdrs[http.CanonicalHeaderKey(k)] = v
	}
	return hdrs
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
	reply *evaluator.Result,
) {
	hdrs := getCheckRequestHeaders(in)
	hattrs := in.GetAttributes().GetRequest().GetHttp()
	evt := log.Info().Str("service", "authorize")
	// request
	evt = evt.Str("request-id", requestid.FromContext(ctx))
	evt = evt.Str("check-request-id", hdrs["X-Request-Id"])
	evt = evt.Str("method", hattrs.GetMethod())
	evt = evt.Interface("headers", hdrs)
	evt = evt.Str("path", hattrs.GetPath())
	evt = evt.Str("host", hattrs.GetHost())
	evt = evt.Str("query", hattrs.GetQuery())
	// reply
	if reply != nil {
		evt = evt.Bool("allow", reply.Status == http.StatusOK)
		evt = evt.Int("status", reply.Status)
		evt = evt.Str("message", reply.Message)
	}
	evt.Msg("authorize check")
}
