package ssh

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/cenkalti/backoff/v4"
	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	"github.com/rs/zerolog"
	otelcode "go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/metric"
	noopmetric "go.opentelemetry.io/otel/metric/noop"
	oteltrace "go.opentelemetry.io/otel/trace"
	nooptrace "go.opentelemetry.io/otel/trace/noop"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	extensions_ssh "github.com/pomerium/envoy-custom/api/extensions/filters/network/ssh"
	xssh "github.com/pomerium/envoy-custom/api/x/recording/formats/ssh"
	"github.com/pomerium/pomerium/authorize/evaluator"
	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/pkg/grpc/databroker"
	identitypb "github.com/pomerium/pomerium/pkg/grpc/identity"
	"github.com/pomerium/pomerium/pkg/grpc/session"
	"github.com/pomerium/pomerium/pkg/identity"
	"github.com/pomerium/pomerium/pkg/identity/oidc"
	"github.com/pomerium/pomerium/pkg/identity/oidc/hosted"
	"github.com/pomerium/pomerium/pkg/policy/criteria"
	"github.com/pomerium/pomerium/pkg/protoutil"
	"github.com/pomerium/pomerium/pkg/ssh/api"
	"github.com/pomerium/pomerium/pkg/ssh/code"
)

const (
	telemetryFingerprintAttribute = "publickey-fingerprint"
)

//go:generate go tool go.uber.org/mock/mockgen -typed -destination ./mock/mock_evaluator.go . SSHEvaluator

//nolint:revive
type SSHEvaluator interface {
	// Evaluates whether a user can connect to this route
	EvaluateSSH(ctx context.Context, streamID uint64, req AuthRequest, initialAuthComplete bool) (*evaluator.Result, error)

	// Evaluates whether a user can attach an upstream tunnel to this route
	EvaluateUpstreamTunnel(ctx context.Context, req AuthRequest, route *config.Policy) (*evaluator.Result, error)
}

type Evaluator interface {
	SSHEvaluator
	databroker.ClientGetter
	InvalidateCacheForRecords(context.Context, ...*databroker.Record)
}

type AuthRequest struct {
	Username         string
	Hostname         string
	PublicKey        string // No encoding
	SessionID        string
	SourceAddress    string
	SessionBindingID string
	LogOnlyIfDenied  bool
}

type Auth struct {
	evaluator      Evaluator
	currentConfig  *atomic.Pointer[config.Config]
	tracerProvider oteltrace.TracerProvider
	tracer         oteltrace.Tracer
	codeIssuer     code.Issuer
	codeMetrics    *code.Metrics
}

type Options struct {
	meter  metric.Meter
	tracer oteltrace.Tracer
}

func (o *Options) Apply(opts ...Option) {
	for _, opt := range opts {
		opt(o)
	}
}

type Option func(o *Options)

func WithMetricMeter(m metric.Meter) Option {
	return func(o *Options) {
		o.meter = m
	}
}

func WithTracer(t oteltrace.Tracer) Option {
	return func(o *Options) {
		o.tracer = t
	}
}

func NewAuth(
	evaluator Evaluator,
	currentConfig *atomic.Pointer[config.Config],
	tracerProvider oteltrace.TracerProvider,
	codeIssuer code.Issuer,
	_ any, // temporary placeholder
	opts ...Option,
) *Auth {
	options := Options{
		meter:  noopmetric.Meter{},
		tracer: nooptrace.Tracer{},
	}
	options.Apply(opts...)
	metrics, err := code.NewMetrics(options.meter)
	if err != nil {
		log.Fatal().Msg("error initializing ssh auth code metrics")
	}

	return &Auth{
		evaluator,
		currentConfig,
		tracerProvider,
		options.tracer,
		codeIssuer,
		metrics,
	}
}

// GetDataBrokerServiceClient implements AuthInterface.
func (a *Auth) GetDataBrokerServiceClient() databroker.DataBrokerServiceClient {
	return a.evaluator.GetDataBrokerServiceClient()
}

func (a *Auth) HandlePublicKeyMethodRequest(
	ctx context.Context,
	streamInfo StreamInfo,
	authInfo StreamAuthInfo,
	user api.UserRequest,
	req *extensions_ssh.PublicKeyMethodRequest,
) (AuthMethodResponse, error) {
	ctx, span := a.tracer.Start(ctx, "authorize.ssh.HandlePublicKeyMethodRequest")
	defer span.End()
	resp, err := a.handlePublicKeyMethodRequest(ctx, streamInfo, authInfo, user, req)
	if err != nil {
		log.Ctx(ctx).Error().Err(err).Msg("ssh publickey auth request error")
		span.SetStatus(otelcode.Error, err.Error())
		// TODO: handle ShowErrorDetails here
		return resp, status.Error(codes.PermissionDenied, "permission denied")
	}
	resp.Validate()
	span.SetStatus(otelcode.Ok, resp.String())
	return resp, err
}

func fingerprintAsStrAttribute(publicKeyFingerprintSha256 []byte) string {
	if publicKeyFingerprintSha256 == nil {
		return ""
	}
	return base64.RawStdEncoding.EncodeToString(publicKeyFingerprintSha256)
}

func authInfoHasPublicKey(info StreamAuthInfo) bool {
	return len(info.GetPublicKey()) > 0 &&
		len(info.GetPublicKeyAlg()) > 0 &&
		len(info.GetPublicKeyFingerprintSha256()) > 0
}

func authInfoHasSession(info StreamAuthInfo) bool {
	return len(info.GetSessionId()) > 0 &&
		len(info.GetSessionBindingId()) > 0
}

func (a *Auth) handlePublicKeyMethodRequest(
	ctx context.Context,
	streamInfo StreamInfo,
	_ StreamAuthInfo,
	user api.UserRequest,
	req *extensions_ssh.PublicKeyMethodRequest,
) (AuthMethodResponse, error) {
	pendingAuthContextUpdates := &extensions_ssh.AuthContext{}

	// First, try authenticating with the public key only, to see if it is allowed
	res, err := a.evaluator.EvaluateSSH(ctx, streamInfo.StreamID, AuthRequest{
		Username:        user.Username(),
		Hostname:        user.Hostname(),
		PublicKey:       string(req.PublicKey),
		SourceAddress:   streamInfo.SourceAddress,
		LogOnlyIfDenied: true,
	}, streamInfo.InitialAuthComplete)
	if err != nil {
		return AuthMethodResponse{}, err
	}

	// Check for non-retriable deny reasons
	if res.HasReason(criteria.ReasonSourceIPUnauthorized) ||
		res.HasReason(criteria.ReasonSSHUsernameUnauthorized) {
		return AuthMethodResponse{}, nil
	}

	if res.HasReason(criteria.ReasonSSHPublickeyUnauthorized) {
		// If the public key itself is not allowed, allow the client to retry
		return AuthMethodResponse{
			AllowMethod:            false,
			NextRequiredAuthMethod: MethodPublicKey,
		}, nil
	}

	// The public key is acceptable
	pendingAuthContextUpdates.PublicKey = req.PublicKey
	pendingAuthContextUpdates.PublicKeyAlg = req.PublicKeyAlg
	pendingAuthContextUpdates.PublicKeyFingerprintSha256 = req.PublicKeyFingerprintSha256

	isPomeriumInternalRoute := res.HasReason(criteria.ReasonPomeriumRoute)
	if !res.HasReason(criteria.ReasonUserUnauthenticated) && !isPomeriumInternalRoute {
		// sanity check
		panic("bug: missing user-unauthenticated deny reason from evaluator result for non-pomerium route")
	}

	// First check if there is a session for this public key
	sessionBindingID, err := sessionIDFromFingerprint(req.PublicKeyFingerprintSha256)
	if err != nil {
		return AuthMethodResponse{}, err
	}
	sessionBinding, _, err := a.resolveSession(ctx, sessionBindingID)
	if err != nil {
		if st, ok := status.FromError(err); ok && st.Code() == codes.NotFound {
			// No session, and one is required
			return AuthMethodResponse{
				AllowMethod:            true, // publickey
				NextRequiredAuthMethod: MethodKeyboardInteractive,
				ContextUpdates:         pendingAuthContextUpdates, // the public key is valid
			}, nil
		}
		// No session, but there was an error checking the databroker or something
		return AuthMethodResponse{}, err
	}

	// Evaluate again, this time with the session info populated.
	res, err = a.evaluator.EvaluateSSH(ctx, streamInfo.StreamID, AuthRequest{
		Username:      user.Username(),
		Hostname:      user.Hostname(),
		PublicKey:     string(req.PublicKey),
		SourceAddress: streamInfo.SourceAddress,

		SessionID:        sessionBinding.SessionId,
		SessionBindingID: sessionBindingID,
		// Keep AccessRequestState unset
	}, streamInfo.InitialAuthComplete)
	if err != nil {
		return AuthMethodResponse{}, err
	}

	if res.HasReason(criteria.ReasonUserUnauthenticated) {
		// The session is not valid
		return AuthMethodResponse{
			AllowMethod:            true, // publickey
			NextRequiredAuthMethod: MethodKeyboardInteractive,
			ContextUpdates:         pendingAuthContextUpdates, // the public key is valid
		}, nil
	}

	return processSessionEvaluateResult(sessionIDs{
		SessionBindingID: sessionBindingID,
		SessionID:        sessionBinding.SessionId,
		UserID:           sessionBinding.UserId,
	}, res, pendingAuthContextUpdates)
}

func (a *Auth) HandleKeyboardInteractiveMethodRequest(
	ctx context.Context,
	streamInfo StreamInfo,
	authInfo StreamAuthInfo,
	user api.UserRequest,
	_ *extensions_ssh.KeyboardInteractiveMethodRequest,
	querier KeyboardInteractiveQuerier,
) (AuthMethodResponse, error) {
	ctx, span := a.tracer.Start(ctx, "authorize.ssh.HandleKeyboardInteractiveMethodRequest")
	defer span.End()
	var policy *config.Policy
	resp, err := a.handleKeyboardInteractiveMethodRequest(ctx, streamInfo, authInfo, user, querier, &policy)
	if err != nil {
		log.Ctx(ctx).Error().Err(err).Msg("ssh keyboard-interactive auth request error")
		span.SetStatus(otelcode.Error, err.Error())
		if policy != nil && policy.ShowErrorDetails {
			return resp, err
		}
		return resp, status.Error(codes.PermissionDenied, "permission denied")
	}
	resp.Validate()
	span.SetStatus(otelcode.Ok, resp.String())
	return resp, err
}

func (a *Auth) handleKeyboardInteractiveMethodRequest(
	ctx context.Context,
	streamInfo StreamInfo,
	authInfo StreamAuthInfo,
	user api.UserRequest,
	querier KeyboardInteractiveQuerier,
	outPolicy **config.Policy,
) (AuthMethodResponse, error) {
	cfg := a.currentConfig.Load()

	fingerprintAttrVal := fingerprintAsStrAttribute(authInfo.GetPublicKeyFingerprintSha256())

	pendingAuthContextUpdates := &extensions_ssh.AuthContext{}

	log.Ctx(ctx).Debug().
		Str("username", user.Username()).
		Str("hostname", user.Hostname()).
		Str(telemetryFingerprintAttribute, fingerprintAttrVal).
		Msg("ssh keyboard-interactive auth request")

	if !authInfoHasPublicKey(authInfo) {
		// Sanity check: this method is only valid if we already accepted a public key.
		panic("bug: public key info missing from auth context")
	}

	policy := cfg.Options.GetRouteForSSHHostname(user.Hostname())
	if outPolicy != nil {
		*outPolicy = policy
	}

	var sessionID, userID, sessionBindingID string

	if !authInfoHasSession(authInfo) {
		// No session (this is the most common case)

		// Initiate the IdP login flow.
		var err error
		sessionBinding, sbID, err := a.handleLogin(ctx, cfg, policy, streamInfo.SourceAddress, authInfo.GetPublicKeyFingerprintSha256(), querier)
		if err != nil {
			return AuthMethodResponse{}, err
		}
		sessionID = sessionBinding.SessionId
		userID = sessionBinding.UserId
		sessionBindingID = sbID
	} else {
		// There is already a valid session, so keyboard-interactive is requested
		// for a different reason
		sessionID = authInfo.GetSessionId()
		userID = authInfo.GetUserId()
		sessionBindingID = authInfo.GetSessionBindingId()

		// (not implemented yet)
		_ = sessionID
		_ = userID
		_ = sessionBindingID

		panic("bug: keyboard-interactive auth request is not valid in this state")
	}

	res, err := a.evaluator.EvaluateSSH(ctx, streamInfo.StreamID, AuthRequest{
		Username:         user.Username(),
		Hostname:         user.Hostname(),
		PublicKey:        string(authInfo.GetPublicKey()),
		SourceAddress:    streamInfo.SourceAddress,
		SessionID:        sessionID,
		SessionBindingID: sessionBindingID,
	}, streamInfo.InitialAuthComplete)
	if err != nil {
		return AuthMethodResponse{}, err
	}
	return processSessionEvaluateResult(sessionIDs{
		SessionBindingID: sessionBindingID,
		SessionID:        sessionID,
		UserID:           userID,
	}, res, pendingAuthContextUpdates)
}

type sessionIDs struct {
	SessionBindingID string
	SessionID        string
	UserID           string
}

func processSessionEvaluateResult(
	ids sessionIDs,
	res *evaluator.Result,
	pendingAuthContextUpdates *extensions_ssh.AuthContext,
) (AuthMethodResponse, error) {
	if res.Allow.Value {
		if !res.Deny.Value {
			// The session is valid and there are no deny reasons
			pendingAuthContextUpdates.SessionBindingId = ids.SessionBindingID
			pendingAuthContextUpdates.SessionId = ids.SessionID
			pendingAuthContextUpdates.UserId = ids.UserID

			return AuthMethodResponse{
				AllowMethod:              true, // publickey
				NoFurtherMethodsRequired: true,
				ContextUpdates:           pendingAuthContextUpdates, // public key + session
			}, nil
		}
	}

	// Deny
	return AuthMethodResponse{}, nil
}

func (a *Auth) handleLogin(
	ctx context.Context,
	cfg *config.Config,
	policy *config.Policy,
	sourceAddr string,
	publicKeyFingerprint []byte,
	querier KeyboardInteractiveQuerier,
) (*session.SessionBinding, string /*sessionBindingID*/, error) {
	ctx, span := a.tracer.Start(ctx, "authorize.ssh.handleLogin")
	defer span.End()

	if cfg.Options.UseStatelessAuthenticateFlow() {
		return nil, "", status.Error(codes.FailedPrecondition, "ssh login is not currently enabled")
	}

	l := log.Ctx(ctx).With().
		Str("protocol", "ssh").
		Str("source-addr", sourceAddr).
		Str(telemetryFingerprintAttribute, fingerprintAsStrAttribute(publicKeyFingerprint)).
		Logger()

	a.codeMetrics.SSHAuthCodeRequestsTotal.Add(ctx, 1)
	a.codeMetrics.PendingSessionInc(ctx)
	defer a.codeMetrics.PendingSessionDec(ctx)
	l.Info().Msg("client requesting authentication")

	bindingKey, err := sessionIDFromFingerprint(publicKeyFingerprint)
	if err != nil {
		return nil, "", a.reportLoginCodeFailure(ctx, l, span, codes.Internal, err.Error())
	}
	idp, authenticator, err := a.getAuthenticator(ctx, cfg, policy)
	if err != nil {
		return nil, "", a.reportLoginCodeFailure(ctx, l, span, codes.Internal, err.Error())
	}
	authURL, _ := cfg.Options.GetAuthenticateURL()
	generatedCode := a.codeIssuer.IssueCode()
	now := timestamppb.Now()

	req := &session.SessionBindingRequest{
		IdpId:     idp.GetId(),
		Key:       bindingKey,
		Protocol:  session.ProtocolSSH,
		State:     session.SessionBindingRequestState_InFlight,
		CreatedAt: now,
		ExpiresAt: timestamppb.New(now.AsTime().Add(a.codeIssuer.CodeTTL())),
		Details: map[string]string{
			session.DetailSourceAddr: sourceAddr,
		},
	}

	ctxT, ca := context.WithDeadline(ctx, req.ExpiresAt.AsTime())
	defer ca()
	startCodeTime := time.Now()
	associatedCode, err := a.codeIssuer.AssociateCode(ctxT, generatedCode, req)
	endCodeTime := time.Now()
	a.codeMetrics.SSHIssueCodeDuration.Record(ctx, endCodeTime.Sub(startCodeTime).Seconds())
	if err != nil {
		return nil, "", a.reportLoginCodeFailure(ctx, l, span, codes.Aborted, "failed to associate a code to this session")
	}
	var prompt string

	query := &url.Values{}
	query.Add("user_code", string(associatedCode))
	promptURI := authURL.ResolveReference(&url.URL{
		Path:     "/.pomerium/sign_in",
		RawQuery: query.Encode(),
	})
	prompt = promptURI.String()
	_, err = querier.Prompt(ctxT, &extensions_ssh.KeyboardInteractiveInfoPrompts{
		Name:        SignInPrompt(authenticator),
		Instruction: prompt,
		Prompts:     nil,
	})
	if err != nil {
		return nil, "", err
	}
	startDecisionTime := time.Now()

	defer func() {
		endDecisionTime := time.Now()
		a.codeMetrics.SSHUserCodeDecisionDuration.Record(ctx, endDecisionTime.Sub(startDecisionTime).Seconds())
	}()

	statusC := a.codeIssuer.OnCodeDecision(ctxT, associatedCode)
	select {
	case <-a.codeIssuer.Done():
		return nil, "", a.reportLoginCodeFailure(ctx, l, span, codes.Internal, "code issuer can no longer process this request")
	case <-ctxT.Done():
		return nil, "", a.reportLoginCodeFailure(ctx, l, span, codes.Canceled, "authentication request timeout")
	case st, ok := <-statusC:
		if !ok {
			return nil, "", a.reportLoginCodeFailure(ctx, l, span, codes.DeadlineExceeded, "authentication request cancelled by user or timeout exceeded")
		}
		switch st.State {
		case session.SessionBindingRequestState_Revoked:
			return nil, "", a.reportLoginCodeFailure(ctx, l, span, codes.PermissionDenied, "user has denied this code")
		case session.SessionBindingRequestState_Accepted:
		default:
			// the code issuer must not send a status reply here with state=InFlight
			panic(fmt.Sprintf("bug: invalid session binding request state in code.Status: %v", st.State))
		}
		if st.BindingKey != bindingKey {
			return nil, "", a.reportLoginCodeFailure(ctx, l, span, codes.Internal, "mismatched binding keys")
		}
		// use ctxT as the parent here so that this will time out in 30s or if the
		// request itself expires, whichever comes first
		ctxca, ca := context.WithTimeout(ctxT, 30*time.Second)
		defer ca()
		b := backoff.WithContext(backoff.NewExponentialBackOff(), ctxca)
		var sessionBinding *session.SessionBinding
		var lastError error
		err := backoff.Retry(func() error {
			sessionBinding, _, lastError = a.resolveSession(ctxca, bindingKey)
			if lastError != nil {
				if databroker.IsNotFound(lastError) {
					return lastError
				}
				return backoff.Permanent(lastError)
			}
			a.evaluator.InvalidateCacheForRecords(ctxca, &databroker.Record{
				Type: "type.googleapis.com/session.SessionBinding",
				Id:   bindingKey,
			})
			return nil
		}, b)
		if err != nil {
			// try to prevent "context canceled" from masking the underlying error
			// if the backoff timed out
			if errors.Is(err, lastError) {
				return nil, "", a.reportLoginCodeFailure(ctx, l, span, codes.Internal, fmt.Sprintf("failed to get matching session binding: %s", err.Error()))
			}
			return nil, "", a.reportLoginCodeFailure(ctx, l, span, codes.Internal, fmt.Sprintf("failed to get matching session binding: %s (last error: %s)", err.Error(), lastError.Error()))
		}
		l.Info().Msg("successfully authenticated")
		span.SetStatus(otelcode.Ok, "successfully authenticated")
		return sessionBinding, bindingKey, nil
	}
}

func SignInPrompt(authenticator identity.Authenticator) string {
	switch authenticator.Name() {
	case hosted.Name, oidc.Name:
		return "Please sign in to continue"
	default:
		return "Please sign in with " + authenticator.Name() + " to continue"
	}
}

func (a *Auth) reportLoginCodeFailure(
	ctx context.Context,
	l zerolog.Logger,
	span oteltrace.Span,
	grpcCode codes.Code,
	errorStr string,
) error {
	switch grpcCode {
	case codes.PermissionDenied:
		a.codeMetrics.SSHAuthCodeRequestFailuresTotal.Add(ctx, 1, metric.WithAttributes(
			code.FailureReason(code.FailureRevoked),
		))
		l.Error().Str(zerolog.ErrorFieldName, errorStr).Msg("code denied")
		span.SetStatus(otelcode.Error, "code denied")
	case codes.Canceled, codes.DeadlineExceeded:
		a.codeMetrics.SSHAuthCodeRequestFailuresTotal.Add(ctx, 1, metric.WithAttributes(
			code.FailureReason(code.FailureTimeout),
		))
		l.Error().Str(zerolog.ErrorFieldName, errorStr).Msg("cancelled")
		span.SetStatus(otelcode.Error, "cancelled")

	default:
		a.codeMetrics.SSHAuthCodeRequestFailuresTotal.Add(ctx, 1, metric.WithAttributes(
			code.FailureReason(code.FailureInternal),
		))
		l.Error().Str(zerolog.ErrorFieldName, errorStr).Msg("internal failure")
		span.SetStatus(otelcode.Error, "internal failure")
	}
	return status.Error(grpcCode, errorStr)
}

var errAccessDenied = status.Error(codes.PermissionDenied, "access denied")

func (a *Auth) EvaluateDelayed(ctx context.Context, streamInfo StreamInfo, authInfo StreamAuthInfo, user api.UserRequest) error {
	req, err := a.sshRequestFromStreamAuthInfo(ctx, streamInfo, authInfo, user)
	if err != nil {
		return err
	}
	res, err := a.evaluator.EvaluateSSH(ctx, streamInfo.StreamID, req, streamInfo.InitialAuthComplete)
	if err != nil {
		return err
	}

	if res.Allow.Value && !res.Deny.Value {
		return nil
	}
	return errAccessDenied
}

// BuildTargetChannelFilters implements [AuthInterface].
func (a *Auth) BuildTargetChannelFilters(ctx context.Context, streamInfo StreamInfo, authInfo StreamAuthInfo, user api.UserRequest) (*corev3.SocketAddress, []*corev3.TypedExtensionConfig, error) {
	hostname := user.Hostname()
	if hostname == "" {
		return nil, nil, fmt.Errorf("no hostname")
	}
	// TODO: optimize looking up routes by hostname
	opts := a.currentConfig.Load().Options
	route := opts.GetRouteForSSHHostname(hostname)
	if route == nil {
		return nil, nil, fmt.Errorf("no route")
	}
	addr := SocketAddressFromString(route)
	if !route.SessionRecording.IsSet || !route.SessionRecording.Value.Enabled.Or(false) {
		return addr, []*corev3.TypedExtensionConfig{}, nil
	}
	sess, err := a.GetSession(ctx, streamInfo, authInfo)
	if err != nil {
		return nil, nil, fmt.Errorf("no session")
	}
	if recordingConfig := buildSSHRecordingConfig(&route.SessionRecording.Value, sess.GetId(), sess.GetUserId()); recordingConfig != nil {
		return addr,
			[]*corev3.TypedExtensionConfig{
				recordingConfig,
			}, nil
	}
	return addr, []*corev3.TypedExtensionConfig{}, nil
}

func SocketAddressFromString(route *config.Policy) *corev3.SocketAddress {
	if route == nil || len(route.To) == 0 {
		return nil
	}
	addr := route.To[0].URL.Host
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return &corev3.SocketAddress{Address: addr}
	}
	sa := &corev3.SocketAddress{Address: host}
	if port, err := strconv.ParseUint(portStr, 10, 32); err == nil {
		sa.PortSpecifier = &corev3.SocketAddress_PortValue{PortValue: uint32(port)}
	}
	return sa
}

func buildSSHRecordingConfig(recCfg *config.SessionRecording, sessionID, userID string) *corev3.TypedExtensionConfig {
	if recCfg == nil {
		return nil
	}
	if !recCfg.Enabled.Or(false) {
		return nil
	}
	ext := &xssh.UpstreamTargetExtensionConfig{
		SessionId: sessionID,
		UserId:    userID,
	}
	return &corev3.TypedExtensionConfig{
		Name:        "session_recording",
		TypedConfig: protoutil.NewAny(ext),
	}
}

func (a *Auth) GetSession(ctx context.Context, _ StreamInfo, authInfo StreamAuthInfo) (*session.Session, error) {
	_, session, err := a.resolveSession(ctx, authInfo.GetSessionBindingId())
	if err != nil {
		return nil, err
	}
	return session, nil
}

func (a *Auth) DeleteSession(ctx context.Context, _ StreamInfo, authInfo StreamAuthInfo) error {
	binding, _, err := a.resolveSession(ctx, authInfo.GetSessionBindingId())
	if err != nil {
		return err
	}
	toInvalidate := []*databroker.Record{}
	sessionErr := session.Delete(ctx, a.evaluator.GetDataBrokerServiceClient(), binding.SessionId)
	a.evaluator.InvalidateCacheForRecords(ctx,
		&databroker.Record{
			Type: "type.googleapis.com/session.Session",
			Id:   binding.SessionId,
		},
	)
	toInvalidate = append(toInvalidate, &databroker.Record{
		Type: "type.googleapis.com/session.Session",
		Id:   binding.SessionId,
	})

	bindingRecs, bindingErr := a.codeIssuer.RevokeSessionBindingBySession(ctx, binding.SessionId)
	if bindingErr == nil && len(bindingRecs) > 0 {
		toInvalidate = append(toInvalidate, bindingRecs...)
	}
	a.evaluator.InvalidateCacheForRecords(ctx, toInvalidate...)
	return errors.Join(sessionErr, bindingErr)
}

func (a *Auth) getAuthenticator(
	ctx context.Context,
	cfg *config.Config,
	policy *config.Policy,
) (*identitypb.Provider, identity.Authenticator, error) {
	redirectURL, err := cfg.Options.GetAuthenticateRedirectURL()
	if err != nil {
		return nil, nil, err
	}

	idp, err := cfg.Options.GetIdentityProviderForPolicy(policy)
	if err != nil {
		return nil, nil, err
	}

	authenticator, err := identity.GetIdentityProvider(ctx, a.tracerProvider, idp, redirectURL,
		cfg.Options.RuntimeFlags[config.RuntimeFlagRefreshSessionAtIDTokenExpiration])
	if err != nil {
		return nil, nil, err
	}

	return idp, authenticator, nil
}

var _ AuthInterface = (*Auth)(nil)

var errInvalidFingerprint = errors.New("invalid public key fingerprint")

func (a *Auth) resolveSession(ctx context.Context, sessionBindingID string) (*session.SessionBinding, *session.Session, error) {
	resp, err := a.evaluator.GetDataBrokerServiceClient().Get(ctx, &databroker.GetRequest{
		Type: "type.googleapis.com/session.SessionBinding",
		Id:   sessionBindingID,
	})
	if err != nil {
		return nil, nil, err
	}
	if resp.Record.DeletedAt != nil {
		return nil, nil, status.Error(codes.NotFound, "session binding deleted")
	}

	var binding session.SessionBinding
	if err := resp.Record.Data.UnmarshalTo(&binding); err != nil {
		return nil, nil, status.Error(codes.Internal, err.Error())
	}
	now := time.Now()
	if binding.ExpiresAt.AsTime().Before(now) {
		return nil, nil, status.Error(codes.NotFound, "session binding no longer valid")
	}
	if binding.Protocol != session.ProtocolSSH {
		return nil, nil, status.Error(codes.Internal, "invalid protocol")
	}
	sessionResp, err := a.evaluator.GetDataBrokerServiceClient().Get(ctx, &databroker.GetRequest{
		Type: "type.googleapis.com/session.Session",
		Id:   binding.SessionId,
	})
	if err != nil {
		return nil, nil, err
	}
	if sessionResp.GetRecord().DeletedAt != nil {
		return nil, nil, status.Error(codes.NotFound, "session deleted")
	}

	var session session.Session
	if err := sessionResp.GetRecord().GetData().UnmarshalTo(&session); err != nil {
		return nil, nil, err
	}

	return &binding, &session, nil
}

func sessionIDFromFingerprint(sha256fingerprint []byte) (string, error) {
	if len(sha256fingerprint) != sha256.Size {
		return "", errInvalidFingerprint
	}
	return "sshkey-SHA256:" + base64.RawStdEncoding.EncodeToString(sha256fingerprint), nil
}

// Converts from StreamAuthInfo to an SSHRequest, assuming the PublicKeyAllow field is not nil.
func (a *Auth) sshRequestFromStreamAuthInfo(_ context.Context, streamInfo StreamInfo, authInfo StreamAuthInfo, user api.UserRequest) (AuthRequest, error) {
	return AuthRequest{
		Username:         user.Username(),
		Hostname:         user.Hostname(),
		PublicKey:        string(authInfo.GetPublicKey()),
		SessionID:        authInfo.GetSessionId(),
		SourceAddress:    streamInfo.SourceAddress,
		SessionBindingID: authInfo.GetSessionBindingId(),
		LogOnlyIfDenied:  streamInfo.InitialAuthComplete,
	}, nil
}
