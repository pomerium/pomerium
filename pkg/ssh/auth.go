package ssh

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"text/template"
	"time"

	oteltrace "go.opentelemetry.io/otel/trace"
	"golang.org/x/oauth2"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	extensions_ssh "github.com/pomerium/envoy-custom/api/extensions/filters/network/ssh"
	"github.com/pomerium/pomerium/authorize/evaluator"
	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/atomicutil"
	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/internal/sessions"
	"github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/grpc/session"
	"github.com/pomerium/pomerium/pkg/grpc/user"
	"github.com/pomerium/pomerium/pkg/identity"
	"github.com/pomerium/pomerium/pkg/identity/manager"
	"github.com/pomerium/pomerium/pkg/policy/criteria"
)

type Evaluator interface {
	EvaluateSSH(context.Context, *Request) (*evaluator.Result, error)
	GetDataBrokerServiceClient() databroker.DataBrokerServiceClient
	InvalidateCacheForRecords(...*databroker.Record)
}

type Request struct {
	Username  string
	Hostname  string
	PublicKey []byte
	SessionID string

	LogOnlyIfDenied bool
}

type Auth struct {
	evaluator      Evaluator
	currentConfig  *atomicutil.Value[*config.Config]
	tracerProvider oteltrace.TracerProvider
}

func NewAuth(
	evaluator Evaluator,
	currentConfig *atomicutil.Value[*config.Config],
	tracerProvider oteltrace.TracerProvider,
) *Auth {
	return &Auth{evaluator, currentConfig, tracerProvider}
}

func (a *Auth) HandlePublicKeyMethodRequest(
	ctx context.Context,
	info StreamAuthInfo,
	req *extensions_ssh.PublicKeyMethodRequest,
) (PublicKeyAuthMethodResponse, error) {
	resp, err := a.handlePublicKeyMethodRequest(ctx, info, req)
	if err != nil {
		log.Ctx(ctx).Error().Err(err).Msg("ssh publickey auth request error")
		return resp, status.Error(codes.Internal, "internal error")
	}
	return resp, err
}

func (a *Auth) handlePublicKeyMethodRequest(
	ctx context.Context,
	info StreamAuthInfo,
	req *extensions_ssh.PublicKeyMethodRequest,
) (PublicKeyAuthMethodResponse, error) {
	sessionID, err := sessionIDFromFingerprint(req.PublicKeyFingerprintSha256)
	if err != nil {
		return PublicKeyAuthMethodResponse{}, err
	}
	sshreq := &Request{
		Username:  *info.Username,
		Hostname:  *info.Hostname,
		PublicKey: req.PublicKey,
		SessionID: sessionID,
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

	res, err := a.evaluator.EvaluateSSH(ctx, sshreq)
	if err != nil {
		return PublicKeyAuthMethodResponse{}, err
	}

	// Interpret the results of policy evaluation.
	if res.HasReason(criteria.ReasonSSHPublickeyUnauthorized) {
		// This public key is not allowed, but the client is free to try a different key.
		return PublicKeyAuthMethodResponse{
			RequireAdditionalMethods: []string{MethodPublicKey},
		}, nil
	} else if res.HasReason(criteria.ReasonUserUnauthenticated) {
		// Mark public key as allowed, to initiate IdP login flow.
		return PublicKeyAuthMethodResponse{
			Allow:                    publicKeyAllowResponse(req.PublicKey),
			RequireAdditionalMethods: []string{MethodKeyboardInteractive},
		}, nil
	} else if res.Allow.Value && !res.Deny.Value {
		// Allowed, no login needed.
		return PublicKeyAuthMethodResponse{
			Allow: publicKeyAllowResponse(req.PublicKey),
		}, nil
	}
	// Denied, no login needed.
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
		return resp, status.Error(codes.Internal, "internal error")
	}
	return resp, err
}

func (a *Auth) handleKeyboardInteractiveMethodRequest(
	ctx context.Context,
	info StreamAuthInfo,
	querier KeyboardInteractiveQuerier,
) (KeyboardInteractiveAuthMethodResponse, error) {
	if info.PublicKeyAllow.Value == nil {
		// Sanity check: this method is only valid if we already accepted a public key.
		return KeyboardInteractiveAuthMethodResponse{}, errPublicKeyAllowNil
	}

	log.Ctx(ctx).Debug().
		Str("username", *info.Username).
		Str("hostname", *info.Hostname).
		Str("publickey-fingerprint", base64.StdEncoding.EncodeToString(info.PublicKeyFingerprintSha256)).
		Msg("ssh keyboard-interactive auth request")

	// Initiate the IdP login flow.
	err := a.handleLogin(ctx, *info.Hostname, info.PublicKeyFingerprintSha256, querier)
	if err != nil {
		return KeyboardInteractiveAuthMethodResponse{}, err
	}

	if err := a.EvaluateDelayed(ctx, info); err != nil {
		// Denied.
		return KeyboardInteractiveAuthMethodResponse{}, nil
	}
	// Allowed.
	return KeyboardInteractiveAuthMethodResponse{
		Allow: &extensions_ssh.KeyboardInteractiveAllowResponse{},
	}, nil
}

func (a *Auth) handleLogin(
	ctx context.Context,
	hostname string,
	publicKeyFingerprint []byte,
	querier KeyboardInteractiveQuerier,
) error {
	// Initiate the IdP login flow.
	authenticator, err := a.getAuthenticator(ctx, hostname)
	if err != nil {
		return err
	}

	resp, err := authenticator.DeviceAuth(ctx)
	if err != nil {
		return err
	}

	// Prompt the user to sign in.
	_, _ = querier.Prompt(ctx, &extensions_ssh.KeyboardInteractiveInfoPrompts{
		Name:        "Please sign in with " + authenticator.Name() + " to continue",
		Instruction: resp.VerificationURIComplete,
		Prompts:     nil,
	})

	var sessionClaims identity.SessionClaims
	token, err := authenticator.DeviceAccessToken(ctx, resp, &sessionClaims)
	if err != nil {
		return err
	}
	sessionID, err := sessionIDFromFingerprint(publicKeyFingerprint)
	if err != nil {
		return err
	}
	return a.saveSession(ctx, sessionID, &sessionClaims, token)
}

var errAccessDenied = status.Error(codes.PermissionDenied, "access denied")

func (a *Auth) EvaluateDelayed(ctx context.Context, info StreamAuthInfo) error {
	req, err := sshRequestFromStreamAuthInfo(info)
	if err != nil {
		return err
	}
	res, err := a.evaluator.EvaluateSSH(ctx, req)
	if err != nil {
		return err
	}

	if res.Allow.Value && !res.Deny.Value {
		return nil
	}
	return errAccessDenied
}

func (a *Auth) FormatSession(ctx context.Context, info StreamAuthInfo) ([]byte, error) {
	sessionID, err := sessionIDFromFingerprint(info.PublicKeyFingerprintSha256)
	if err != nil {
		return nil, err
	}
	session, err := session.Get(ctx, a.evaluator.GetDataBrokerServiceClient(), sessionID)
	if err != nil {
		return nil, err
	}
	var b bytes.Buffer
	err = sessionInfoTmpl.Execute(&b, session)
	if err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

func (a *Auth) DeleteSession(ctx context.Context, info StreamAuthInfo) error {
	sessionID, err := sessionIDFromFingerprint(info.PublicKeyFingerprintSha256)
	if err != nil {
		return err
	}
	err = session.Delete(ctx, a.evaluator.GetDataBrokerServiceClient(), sessionID)
	a.evaluator.InvalidateCacheForRecords(&databroker.Record{
		Type: "type.googleapis.com/session.Session",
		Id:   sessionID,
	})
	return err
}

func (a *Auth) saveSession(
	ctx context.Context,
	id string,
	claims *identity.SessionClaims,
	token *oauth2.Token,
) error {
	now := time.Now()
	nowpb := timestamppb.New(now)
	sessionLifetime := a.currentConfig.Load().Options.CookieExpire

	state := sessions.State{ID: id}
	if err := claims.Claims.Claims(&state); err != nil {
		return err
	}

	sess := &session.Session{
		Id:         id,
		UserId:     state.UserID(),
		IssuedAt:   nowpb,
		AccessedAt: nowpb,
		ExpiresAt:  timestamppb.New(now.Add(sessionLifetime)),
		OauthToken: manager.ToOAuthToken(token),
		Audience:   state.Audience,
	}
	sess.SetRawIDToken(claims.RawIDToken)
	sess.AddClaims(claims.Flatten())

	u, _ := user.Get(ctx, a.evaluator.GetDataBrokerServiceClient(), sess.GetUserId())
	if u == nil {
		// if no user exists yet, create a new one
		u = &user.User{
			Id: sess.GetUserId(),
		}
	}
	u.PopulateFromClaims(claims.Claims)
	resp, err := databroker.Put(ctx, a.evaluator.GetDataBrokerServiceClient(), u)
	if err != nil {
		return err
	}
	a.evaluator.InvalidateCacheForRecords(resp.GetRecord())

	resp, err = session.Put(ctx, a.evaluator.GetDataBrokerServiceClient(), sess)
	if err != nil {
		return err
	}
	a.evaluator.InvalidateCacheForRecords(resp.GetRecord())
	return nil
}

func (a *Auth) getAuthenticator(ctx context.Context, hostname string) (identity.Authenticator, error) {
	opts := a.currentConfig.Load().Options

	redirectURL, err := opts.GetAuthenticateRedirectURL()
	if err != nil {
		return nil, err
	}

	idp, err := opts.GetIdentityProviderForPolicy(opts.GetRouteForSSHHostname(hostname))
	if err != nil {
		return nil, err
	}

	return identity.GetIdentityProvider(ctx, a.tracerProvider, idp, redirectURL)
}

var _ AuthInterface = (*Auth)(nil)

var errInvalidFingerprint = errors.New("invalid public key fingerprint")

func sessionIDFromFingerprint(sha256fingerprint []byte) (string, error) {
	if len(sha256fingerprint) != sha256.Size {
		return "", errInvalidFingerprint
	}
	return "sshkey-SHA256:" + base64.StdEncoding.EncodeToString(sha256fingerprint), nil
}

var errPublicKeyAllowNil = errors.New("expected PublicKeyAllow message not to be nil")

// Converts from StreamAuthInfo to an SSHRequest, assuming the PublicKeyAllow field is not nil.
func sshRequestFromStreamAuthInfo(info StreamAuthInfo) (*Request, error) {
	if info.PublicKeyAllow.Value == nil {
		return nil, errPublicKeyAllowNil
	}
	sessionID, err := sessionIDFromFingerprint(info.PublicKeyFingerprintSha256)
	if err != nil {
		return nil, err
	}

	return &Request{
		Username:  *info.Username,
		Hostname:  *info.Hostname,
		PublicKey: info.PublicKeyAllow.Value.PublicKey,
		SessionID: sessionID,

		LogOnlyIfDenied: info.InitialAuthComplete,
	}, nil
}

var sessionInfoTmpl = template.Must(template.New("session-info").Parse(`
User ID:    {{.UserId}}
Session ID: {{.Id}}
Expires at: {{.ExpiresAt.AsTime}}
Claims:
{{- range $k, $v := .Claims }}
  {{ $k }}: {{ $v.AsSlice }}
{{- end }}
`))
