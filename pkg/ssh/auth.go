package ssh

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
	"slices"
	"sync/atomic"
	"time"

	"github.com/cenkalti/backoff/v4"
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
	"github.com/pomerium/pomerium/authorize/evaluator"
	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/pkg/grpc/databroker"
	identitypb "github.com/pomerium/pomerium/pkg/grpc/identity"
	"github.com/pomerium/pomerium/pkg/grpc/session"
	"github.com/pomerium/pomerium/pkg/identity"
	"github.com/pomerium/pomerium/pkg/policy/criteria"
	"github.com/pomerium/pomerium/pkg/ssh/code"
)

const (
	telemetryFingerprintAttribute = "publickey-fingerprint"
)

//go:generate go run go.uber.org/mock/mockgen -typed -destination ./mock/mock_evaluator.go . SSHEvaluator

//nolint:revive
type SSHEvaluator interface {
	EvaluateSSH(ctx context.Context, streamID uint64, req AuthRequest, initialAuthComplete bool) (*evaluator.Result, error)
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
	info StreamAuthInfo,
	req *extensions_ssh.PublicKeyMethodRequest,
) (PublicKeyAuthMethodResponse, error) {
	ctx, span := a.tracer.Start(ctx, "authorize.ssh.HandlePublicKeyMethodRequest")
	defer span.End()
	resp, err := a.handlePublicKeyMethodRequest(ctx, info, req)
	if err != nil {
		log.Ctx(ctx).Error().Err(err).Msg("ssh publickey auth request error")
		span.SetStatus(otelcode.Error, "internal error")
		return resp, status.Error(codes.Internal, "internal error")
	}
	return resp, err
}

func fingerprintAsStrAttribute(publicKeyFingerprintSha256 []byte) string {
	if publicKeyFingerprintSha256 == nil {
		return ""
	}
	return base64.RawStdEncoding.EncodeToString(publicKeyFingerprintSha256)
}

func (a *Auth) handlePublicKeyMethodRequest(
	ctx context.Context,
	info StreamAuthInfo,
	req *extensions_ssh.PublicKeyMethodRequest,
) (PublicKeyAuthMethodResponse, error) {
	ctx, span := a.tracer.Start(ctx, "authorize.ssh.handlePublicKeyMethodRequest")
	defer span.End()
	sessionID, err := a.resolveSessionIDFromFingerprint(ctx, req.PublicKeyFingerprintSha256)
	if err != nil {
		if st, ok := status.FromError(err); ok && st.Code() == codes.NotFound {
			span.SetStatus(otelcode.Ok, "must reauthenticated")
			return PublicKeyAuthMethodResponse{
				Allow:                    publicKeyAllowResponse(req.PublicKey),
				RequireAdditionalMethods: []string{MethodKeyboardInteractive},
			}, nil
		}
		return PublicKeyAuthMethodResponse{}, err
	}
	bindingID, _ := sessionIDFromFingerprint(req.PublicKeyFingerprintSha256)
	sshreq := AuthRequest{
		Username:         *info.Username,
		Hostname:         *info.Hostname,
		PublicKey:        string(req.PublicKey),
		SessionID:        sessionID,
		SessionBindingID: bindingID,
		SourceAddress:    info.SourceAddress,
	}
	log.Ctx(ctx).Debug().
		Str("username", *info.Username).
		Str("hostname", *info.Hostname).
		Str("session-id", sessionID).
		Msg("ssh publickey auth request")

	// Special case: internal command (e.g. routes portal).
	if *info.Hostname == "" {
		_, err := session.Get(ctx, a.evaluator.GetDataBrokerServiceClient(), sessionID)
		if status.Code(err) == codes.NotFound {
			// Require IdP login.
			return PublicKeyAuthMethodResponse{
				Allow:                    publicKeyAllowResponse(req.PublicKey),
				RequireAdditionalMethods: []string{MethodKeyboardInteractive},
			}, nil
		} else if err != nil {
			return PublicKeyAuthMethodResponse{}, err
		}
	}

	res, err := a.evaluator.EvaluateSSH(ctx, info.StreamID, sshreq, info.InitialAuthComplete)
	if err != nil {
		span.SetStatus(otelcode.Error, "internal error : evaluate")
		return PublicKeyAuthMethodResponse{}, err
	}

	// Interpret the results of policy evaluation.
	if res.HasReason(criteria.ReasonSSHPublickeyUnauthorized) {
		// This public key is not allowed, but the client is free to try a different key.
		span.SetStatus(otelcode.Ok, "public key not allowed")
		return PublicKeyAuthMethodResponse{
			RequireAdditionalMethods: []string{MethodPublicKey},
		}, nil
	} else if res.HasReason(criteria.ReasonUserUnauthenticated) {
		// Mark public key as allowed, to initiate IdP login flow.
		span.SetStatus(otelcode.Ok, "un-authenticated")
		return PublicKeyAuthMethodResponse{
			Allow:                    publicKeyAllowResponse(req.PublicKey),
			RequireAdditionalMethods: []string{MethodKeyboardInteractive},
		}, nil
	} else if res.Allow.Value && !res.Deny.Value {
		// Allowed, no login needed.
		span.SetStatus(otelcode.Ok, "allowed")
		return PublicKeyAuthMethodResponse{
			Allow: publicKeyAllowResponse(req.PublicKey),
		}, nil
	}
	// Denied, no login needed.
	span.SetStatus(otelcode.Ok, "denied")
	return PublicKeyAuthMethodResponse{}, nil
}

func publicKeyAllowResponse(publicKey []byte) *extensions_ssh.PublicKeyAllowResponse {
	return &extensions_ssh.PublicKeyAllowResponse{
		PublicKey: publicKey,
		Permissions: &extensions_ssh.Permissions{
			PermitPortForwarding:  true,
			PermitAgentForwarding: true,
			PermitX11Forwarding:   true,
			PermitPty:             true,
			PermitUserRc:          true,
			ValidStartTime:        timestamppb.New(time.Now().Add(-1 * time.Minute)),
			ValidEndTime:          timestamppb.New(time.Now().Add(1 * time.Hour)),
		},
	}
}

func (a *Auth) HandleKeyboardInteractiveMethodRequest(
	ctx context.Context,
	info StreamAuthInfo,
	_ *extensions_ssh.KeyboardInteractiveMethodRequest,
	querier KeyboardInteractiveQuerier,
) (KeyboardInteractiveAuthMethodResponse, error) {
	resp, err := a.handleKeyboardInteractiveMethodRequest(ctx, info, querier)
	if err != nil {
		log.Ctx(ctx).Error().Err(err).Msg("ssh keyboard-interactive auth request error")
		if _, ok := status.FromError(err); !ok {
			return resp, status.Error(codes.Internal, err.Error())
		}
		return resp, err
	}
	return resp, err
}

func (a *Auth) handleKeyboardInteractiveMethodRequest(
	ctx context.Context,
	info StreamAuthInfo,
	querier KeyboardInteractiveQuerier,
) (KeyboardInteractiveAuthMethodResponse, error) {
	fingerprintAttrVal := fingerprintAsStrAttribute(info.PublicKeyFingerprintSha256)
	ctx, span := a.tracer.Start(ctx, "authorize.ssh.handleKeyboardInteractiveMethodRequest")
	defer span.End()
	if info.PublicKeyAllow.Value == nil {
		// Sanity check: this method is only valid if we already accepted a public key.
		return KeyboardInteractiveAuthMethodResponse{}, errPublicKeyAllowNil
	}

	log.Ctx(ctx).Debug().
		Str("username", *info.Username).
		Str("hostname", *info.Hostname).
		Str(telemetryFingerprintAttribute, fingerprintAttrVal).
		Msg("ssh keyboard-interactive auth request")

	// Initiate the IdP login flow.
	err := a.handleLogin(ctx, *info.Hostname, info.SourceAddress, info.PublicKeyFingerprintSha256, querier)
	if err != nil {
		span.SetStatus(otelcode.Error, "login failed")
		return KeyboardInteractiveAuthMethodResponse{}, err
	}

	if err := a.EvaluateDelayed(ctx, info); err != nil {
		// Denied.
		span.SetStatus(otelcode.Ok, "denied")
		return KeyboardInteractiveAuthMethodResponse{}, nil
	}
	// Allowed.
	span.SetStatus(otelcode.Ok, "allowed")
	return KeyboardInteractiveAuthMethodResponse{
		Allow: &extensions_ssh.KeyboardInteractiveAllowResponse{},
	}, nil
}

func (a *Auth) handleLogin(
	ctx context.Context,
	hostname string,
	sourceAddr string,
	publicKeyFingerprint []byte,
	querier KeyboardInteractiveQuerier,
) (err error) {
	ctx, span := a.tracer.Start(ctx, "authorize.ssh.handleLogin")
	defer span.End()

	cfg := a.currentConfig.Load()
	if cfg.Options.UseStatelessAuthenticateFlow() {
		return status.Error(codes.FailedPrecondition, "ssh login is not currently enabled")
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
		return a.reportLoginCodeFailure(ctx, l, span, codes.Internal, err.Error())
	}
	idp, authenticator, err := a.getAuthenticator(ctx, hostname)
	if err != nil {
		return a.reportLoginCodeFailure(ctx, l, span, codes.Internal, err.Error())
	}
	authURL, _ := cfg.Options.GetInternalAuthenticateURL()
	generatedCode := a.codeIssuer.IssueCode()
	now := timestamppb.Now()

	req := &session.SessionBindingRequest{
		IdpId:     idp.GetId(),
		Key:       bindingKey,
		Protocol:  session.ProtocolSSH,
		State:     session.SessionBindingRequestState_InFlight,
		CreatedAt: now,
		ExpiresAt: timestamppb.New(now.AsTime().Add(code.DefaultCodeTTL)),
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
		return a.reportLoginCodeFailure(ctx, l, span, codes.Aborted, "failed to associate a code to this session")
	}
	var prompt string

	query := &url.Values{}
	query.Add("user_code", string(associatedCode))
	promptURI := authURL.ResolveReference(&url.URL{
		Path:     "/.pomerium/sign_in",
		RawQuery: query.Encode(),
	})
	prompt = promptURI.String()
	_, _ = querier.Prompt(ctxT, &extensions_ssh.KeyboardInteractiveInfoPrompts{
		Name:        "Please sign in with " + authenticator.Name() + " to continue",
		Instruction: prompt,
		Prompts:     nil,
	})
	startDecisionTime := time.Now()

	defer func() {
		endDecisionTime := time.Now()
		a.codeMetrics.SSHUserCodeDecisionDuration.Record(ctx, endDecisionTime.Sub(startDecisionTime).Seconds())
	}()

	statusC := a.codeIssuer.OnCodeDecision(ctxT, associatedCode)
	select {
	case <-a.codeIssuer.Done():
		return a.reportLoginCodeFailure(ctx, l, span, codes.Internal, "code issuer can no longer process this request")
	case <-ctxT.Done():
		return a.reportLoginCodeFailure(ctx, l, span, codes.Canceled, "authentication request timeout")
	case st, ok := <-statusC:
		if !ok {
			return a.reportLoginCodeFailure(ctx, l, span, codes.DeadlineExceeded, "authentication request cancelled by user or timeout exceeded")
		}
		if st.State == session.SessionBindingRequestState_Revoked {
			return a.reportLoginCodeFailure(ctx, l, span, codes.PermissionDenied, "user has denied this code")
		}
		if st.BindingKey != bindingKey {
			return a.reportLoginCodeFailure(ctx, l, span, codes.Internal, "mismatched binding keys")
		}
		ctxca, ca := context.WithTimeout(context.Background(), 30*time.Second)
		defer ca()
		b := backoff.WithContext(backoff.NewExponentialBackOff(), ctxca)
		client := a.evaluator.GetDataBrokerServiceClient()
		err := backoff.Retry(func() error {
			rec, err := client.Get(ctxca, &databroker.GetRequest{
				Type: "type.googleapis.com/session.SessionBinding",
				Id:   bindingKey,
			})
			if rec.Record.DeletedAt != nil {
				return fmt.Errorf("stale record")
			}
			if err != nil {
				return err
			}
			a.evaluator.InvalidateCacheForRecords(ctxca, rec.GetRecord())
			return nil
		}, b)
		if err != nil {
			return a.reportLoginCodeFailure(ctx, l, span, codes.Internal, fmt.Sprintf("failed to get matching session binding : %s", err.Error()))
		}
		l.Info().Msg("successfully authenticated")
		span.SetStatus(otelcode.Ok, "successfully authenticated")
		return nil
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

func (a *Auth) EvaluateDelayed(ctx context.Context, info StreamAuthInfo) error {
	req, err := a.sshRequestFromStreamAuthInfo(ctx, info)
	if err != nil {
		return err
	}
	res, err := a.evaluator.EvaluateSSH(ctx, info.StreamID, req, info.InitialAuthComplete)
	if err != nil {
		return err
	}

	if res.Allow.Value && !res.Deny.Value {
		return nil
	}
	return errAccessDenied
}

// EvaluatePortForward implements AuthInterface.
func (a *Auth) EvaluatePortForward(ctx context.Context, info StreamAuthInfo, route *config.Policy) error {
	req, err := a.sshRequestFromStreamAuthInfo(ctx, info)
	if err != nil {
		return err
	}
	res, err := a.evaluator.EvaluateUpstreamTunnel(ctx, req, route)
	if err != nil {
		return err
	}

	if res.Allow.Value && !res.Deny.Value {
		return nil
	}
	return errAccessDenied
}

func (a *Auth) FormatSession(ctx context.Context, info StreamAuthInfo) ([]byte, error) {
	sessionID, err := a.resolveSessionIDFromFingerprint(ctx, info.PublicKeyFingerprintSha256)
	if err != nil {
		return nil, err
	}
	session, err := session.Get(ctx, a.evaluator.GetDataBrokerServiceClient(), sessionID)
	if err != nil {
		return nil, err
	}
	var b bytes.Buffer
	fmt.Fprintf(&b, "User ID:    %s\n", session.UserId)
	fmt.Fprintf(&b, "Session ID: %s\n", sessionID)
	fmt.Fprintf(&b, "Expires at: %s (in %s)\n",
		session.ExpiresAt.AsTime().String(),
		time.Until(session.ExpiresAt.AsTime()).Round(time.Second))
	fmt.Fprintf(&b, "Claims:\n")
	keys := make([]string, 0, len(session.Claims))
	for key := range session.Claims {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	for _, key := range keys {
		fmt.Fprintf(&b, "  %s: ", key)
		vs := session.Claims[key].AsSlice()
		if len(vs) != 1 {
			b.WriteRune('[')
		}
		if len(vs) == 1 {
			switch key {
			case "iat":
				d, _ := vs[0].(float64)
				t := time.Unix(int64(d), 0)
				fmt.Fprintf(&b, "%s (%s ago)", t, time.Since(t).Round(time.Second))
			case "exp":
				d, _ := vs[0].(float64)
				t := time.Unix(int64(d), 0)
				fmt.Fprintf(&b, "%s (in %s)", t, time.Until(t).Round(time.Second))
			default:
				fmt.Fprintf(&b, "%#v", vs[0])
			}
		} else if len(vs) > 1 {
			for i, v := range vs {
				fmt.Fprintf(&b, "%#v", v)
				if i < len(vs)-1 {
					b.WriteString(", ")
				}
			}
		}
		if len(vs) != 1 {
			b.WriteRune(']')
		}
		b.WriteRune('\n')
	}
	return b.Bytes(), nil
}

func (a *Auth) DeleteSession(ctx context.Context, info StreamAuthInfo) error {
	sessionID, err := a.resolveSessionIDFromFingerprint(ctx, info.PublicKeyFingerprintSha256)
	if err != nil {
		return err
	}
	toInvalidate := []*databroker.Record{}
	sessionErr := session.Delete(ctx, a.evaluator.GetDataBrokerServiceClient(), sessionID)
	a.evaluator.InvalidateCacheForRecords(ctx,
		&databroker.Record{
			Type: "type.googleapis.com/session.Session",
			Id:   sessionID,
		},
	)
	toInvalidate = append(toInvalidate, &databroker.Record{
		Type: "type.googleapis.com/session.Session",
		Id:   sessionID,
	})

	bindingRecs, bindingErr := a.codeIssuer.RevokeSessionBindingBySession(ctx, sessionID)
	if bindingErr == nil && len(bindingRecs) > 0 {
		toInvalidate = append(toInvalidate, bindingRecs...)
	}
	a.evaluator.InvalidateCacheForRecords(ctx, toInvalidate...)
	return errors.Join(sessionErr, bindingErr)
}

func (a *Auth) getAuthenticator(ctx context.Context, hostname string) (*identitypb.Provider, identity.Authenticator, error) {
	opts := a.currentConfig.Load().Options

	redirectURL, err := opts.GetAuthenticateRedirectURL()
	if err != nil {
		return nil, nil, err
	}

	idp, err := opts.GetIdentityProviderForPolicy(opts.GetRouteForSSHHostname(hostname))
	if err != nil {
		return nil, nil, err
	}

	authenticator, err := identity.GetIdentityProvider(ctx, a.tracerProvider, idp, redirectURL,
		opts.RuntimeFlags[config.RuntimeFlagRefreshSessionAtIDTokenExpiration])
	if err != nil {
		return nil, nil, err
	}

	return idp, authenticator, nil
}

var _ AuthInterface = (*Auth)(nil)

var errInvalidFingerprint = errors.New("invalid public key fingerprint")

func (a *Auth) resolveSessionID(ctx context.Context, sessionBindingID string) (string, error) {
	resp, err := a.evaluator.GetDataBrokerServiceClient().Get(ctx, &databroker.GetRequest{
		Type: "type.googleapis.com/session.SessionBinding",
		Id:   sessionBindingID,
	})
	if err != nil {
		return "", err
	}
	if resp.Record.DeletedAt != nil {
		return "", status.Error(codes.NotFound, "session binding deleted")
	}

	var binding session.SessionBinding
	if err := resp.Record.Data.UnmarshalTo(&binding); err != nil {
		return "", status.Error(codes.Internal, err.Error())
	}
	now := time.Now()
	if binding.ExpiresAt.AsTime().Before(now) {
		return "", status.Error(codes.NotFound, "session binding no longer valid")
	}
	if binding.Protocol != session.ProtocolSSH {
		return "", status.Error(codes.Internal, "invalid protocol")
	}
	sessionResp, err := a.evaluator.GetDataBrokerServiceClient().Get(ctx, &databroker.GetRequest{
		Type: "type.googleapis.com/session.Session",
		Id:   binding.SessionId,
	})
	if err != nil {
		return "", err
	}
	if sessionResp.GetRecord().DeletedAt != nil {
		return "", status.Error(codes.NotFound, "session deleted")
	}

	return binding.SessionId, nil
}

func sessionIDFromFingerprint(sha256fingerprint []byte) (string, error) {
	if len(sha256fingerprint) != sha256.Size {
		return "", errInvalidFingerprint
	}
	return "sshkey-SHA256:" + base64.RawStdEncoding.EncodeToString(sha256fingerprint), nil
}

func (a *Auth) resolveSessionIDFromFingerprint(ctx context.Context, sha256fingerprint []byte) (string, error) {
	id, err := sessionIDFromFingerprint(sha256fingerprint)
	if err != nil {
		return "", err
	}
	return a.resolveSessionID(ctx, id)
}

var errPublicKeyAllowNil = errors.New("expected PublicKeyAllow message not to be nil")

// Converts from StreamAuthInfo to an SSHRequest, assuming the PublicKeyAllow field is not nil.
func (a *Auth) sshRequestFromStreamAuthInfo(ctx context.Context, info StreamAuthInfo) (AuthRequest, error) {
	if info.PublicKeyAllow.Value == nil {
		return AuthRequest{}, errPublicKeyAllowNil
	}
	sessionID, err := a.resolveSessionIDFromFingerprint(ctx, info.PublicKeyFingerprintSha256)
	if err != nil {
		return AuthRequest{}, err
	}

	bindingID, _ := sessionIDFromFingerprint(info.PublicKeyFingerprintSha256)
	return AuthRequest{
		Username:         *info.Username,
		Hostname:         *info.Hostname,
		PublicKey:        string(info.PublicKeyAllow.Value.PublicKey),
		SessionID:        sessionID,
		SourceAddress:    info.SourceAddress,
		SessionBindingID: bindingID,

		LogOnlyIfDenied: info.InitialAuthComplete,
	}, nil
}
