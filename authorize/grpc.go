package authorize

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	envoy_service_auth_v3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/pomerium/pomerium/authorize/checkrequest"
	"github.com/pomerium/pomerium/authorize/evaluator"
	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/config/envoyconfig"
	"github.com/pomerium/pomerium/internal/httputil"
	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/internal/sessions"
	"github.com/pomerium/pomerium/pkg/contextutil"
	"github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/grpc/user"
	"github.com/pomerium/pomerium/pkg/storage"
	"github.com/pomerium/pomerium/pkg/telemetry/requestid"
)

// Check implements the envoy auth server gRPC endpoint.
func (a *Authorize) Check(ctx context.Context, in *envoy_service_auth_v3.CheckRequest) (*envoy_service_auth_v3.CheckResponse, error) {
	ctx, span := a.tracer.Start(ctx, "authorize.grpc.Check")
	defer span.End()

	querier := storage.NewCachingQuerier(
		storage.NewQuerier(a.state.Load().dataBrokerClient),
		storage.GlobalCache,
	)
	ctx = storage.WithQuerier(ctx, querier)

	state := a.state.Load()

	// convert the incoming envoy-style http request into a go-style http request
	hreq := getHTTPRequestFromCheckRequest(in)
	requestID := requestid.FromHTTPHeader(hreq.Header)
	ctx = requestid.WithValue(ctx, requestID)

	req, err := a.getEvaluatorRequestFromCheckRequest(ctx, in)
	if err != nil {
		log.Ctx(ctx).Error().Err(err).Str("request-id", requestID).Msg("error building evaluator request")
		return nil, err
	}

	// load the session
	s, err := a.loadSession(ctx, hreq, req)
	if errors.Is(err, sessions.ErrInvalidSession) {
		// ENG-2172: if this is an invalid session, don't evaluate policy, return forbidden
		return a.deniedResponse(ctx, in, int32(http.StatusForbidden), http.StatusText(http.StatusForbidden), nil)
	} else if err != nil {
		return nil, fmt.Errorf("error loading session: %w", err)
	}

	// if there's a session or service account, load the user
	var u *user.User
	if s != nil {
		req.Session.ID = s.GetId()
		u, _ = a.getDataBrokerUser(ctx, s.GetUserId()) // ignore any missing user error
	}

	res, err := state.evaluator.Evaluate(ctx, req)
	if err != nil {
		log.Ctx(ctx).Error().Err(err).Str("request-id", requestID).Msg("error during OPA evaluation")
		return nil, err
	}

	// if show error details is enabled, attach the policy evaluation traces
	if req.Policy != nil && req.Policy.ShowErrorDetails {
		ctx = contextutil.WithPolicyEvaluationTraces(ctx, res.Traces)
	}

	resp, err := a.handleResult(ctx, in, req, res)
	if err != nil {
		log.Ctx(ctx).Error().Err(err).Str("request-id", requestID).Msg("grpc check ext_authz_error")
	}
	a.logAuthorizeCheck(ctx, req, res, s, u)
	return resp, err
}

func (a *Authorize) loadSession(
	ctx context.Context,
	hreq *http.Request,
	req *evaluator.Request,
) (s sessionOrServiceAccount, err error) {
	requestID := requestid.FromHTTPHeader(hreq.Header)

	// attempt to create a session from an incoming idp token
	s, err = config.NewIncomingIDPTokenSessionCreator(
		func(ctx context.Context, recordType, recordID string) (*databroker.Record, error) {
			return storage.GetDataBrokerRecord(ctx, recordType, recordID, 0)
		},
		func(ctx context.Context, records []*databroker.Record) error {
			_, err := a.state.Load().dataBrokerClient.Put(ctx, &databroker.PutRequest{
				Records: records,
			})
			if err != nil {
				return err
			}
			storage.InvalidateCacheForDataBrokerRecords(ctx, records...)
			return nil
		},
	).CreateSession(ctx, a.currentConfig.Load(), req.Policy, hreq)
	if err == nil {
		return s, nil
	} else if !errors.Is(err, sessions.ErrNoSessionFound) {
		log.Ctx(ctx).Info().
			Str("request-id", requestID).
			Err(err).
			Msg("error creating session for incoming idp token")
		return nil, err
	}

	sessionState, _ := a.state.Load().sessionStore.LoadSessionStateAndCheckIDP(hreq)
	if sessionState == nil {
		return nil, nil
	}

	s, err = a.getDataBrokerSessionOrServiceAccount(ctx, sessionState.ID, sessionState.DatabrokerRecordVersion)
	if status.Code(err) == codes.Unavailable {
		log.Ctx(ctx).Debug().Str("request-id", requestID).Err(err).Msg("temporary error checking authorization: data broker unavailable")
		return nil, err
	} else if err != nil {
		log.Ctx(ctx).Info().Err(err).Str("request-id", requestID).Msg("clearing session due to missing or invalid session or service account")
		return nil, nil
	}

	return s, nil
}

func (a *Authorize) getEvaluatorRequestFromCheckRequest(
	ctx context.Context,
	in *envoy_service_auth_v3.CheckRequest,
) (*evaluator.Request, error) {
	attrs := in.GetAttributes()
	req := &evaluator.Request{
		IsInternal: envoyconfig.ExtAuthzContextExtensionsIsInternal(attrs.GetContextExtensions()),
		HTTP:       evaluator.RequestHTTPFromCheckRequest(ctx, in),
	}
	req.Policy = a.getMatchingPolicy(envoyconfig.ExtAuthzContextExtensionsRouteID(attrs.GetContextExtensions()))
	return req, nil
}

func (a *Authorize) getMatchingPolicy(routeID uint64) *config.Policy {
	options := a.currentConfig.Load().Options

	for p := range options.GetAllPolicies() {
		id, _ := p.RouteID()
		if id == routeID {
			return p
		}
	}

	return nil
}

func getHTTPRequestFromCheckRequest(req *envoy_service_auth_v3.CheckRequest) *http.Request {
	hattrs := req.GetAttributes().GetRequest().GetHttp()
	u := checkrequest.GetURL(req)
	hreq := &http.Request{
		Method:     hattrs.GetMethod(),
		URL:        &u,
		Header:     make(http.Header),
		Body:       io.NopCloser(strings.NewReader(hattrs.GetBody())),
		Host:       hattrs.GetHost(),
		RequestURI: hattrs.GetPath(),
	}
	for k, v := range getCheckRequestHeaders(req) {
		hreq.Header.Set(k, v)
	}
	return hreq
}

func getCheckRequestHeaders(req *envoy_service_auth_v3.CheckRequest) map[string]string {
	hdrs := make(map[string]string)
	ch := req.GetAttributes().GetRequest().GetHttp().GetHeaders()
	for k, v := range ch {
		hdrs[httputil.CanonicalHeaderKey(k)] = v
	}
	return hdrs
}
