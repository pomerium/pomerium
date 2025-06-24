package ssh

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"html/template"
	"time"

	oteltrace "go.opentelemetry.io/otel/trace"
	"golang.org/x/oauth2"
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

type PolicyEvaluator interface {
	// XXX - should this also take a parameter whether to log to the authorize log?
	EvaluateSSH(context.Context, *SSHRequest) (*evaluator.Result, error)
}

type SSHRequest struct {
	Username                 string
	Hostname                 string
	PublicKey                []byte
	SessionID                string
	SessionRecordVersionHint uint64
}

type SSHAuth struct {
	evaluator        PolicyEvaluator
	dataBrokerClient databroker.DataBrokerServiceClient
	currentConfig    *atomicutil.Value[*config.Config]
	tracerProvider   oteltrace.TracerProvider
}

func NewSSHAuth(
	evaluator PolicyEvaluator,
	client databroker.DataBrokerServiceClient,
	currentConfig *atomicutil.Value[*config.Config],
	tracerProvider oteltrace.TracerProvider,
) *SSHAuth {
	return &SSHAuth{evaluator, client, currentConfig, tracerProvider}
}

func (a *SSHAuth) HandlePublicKeyMethodRequest(
	ctx context.Context,
	info StreamAuthInfo,
	req *extensions_ssh.PublicKeyMethodRequest,
) ([]AuthMethodResult, error) {
	sshreq := &SSHRequest{
		Username:  info.Username,
		Hostname:  info.Hostname,
		PublicKey: req.PublicKey,
		SessionID: sessionIDFromFingerprint(req.PublicKeyFingerprintSha256),
	}
	log.Ctx(ctx).Info().Interface("ssh-request", sshreq).Msg("HandlePublicKeyMethodRequest")
	res, err := a.evaluator.EvaluateSSH(ctx, sshreq)
	if err != nil {
		return nil, err
	}

	// Interpret the results of policy evaluation.
	if res.HasReason(criteria.ReasonSSHPublickeyUnauthorized) {
		// This public key is not allowed, but the client is free to try a different key.
		return []AuthMethodResult{
			DenyPublicKey(),
		}, nil
	} else if res.HasReason(criteria.ReasonUserUnauthenticated) {
		// Mark public key as allowed, to initiate IdP login flow.
		return []AuthMethodResult{
			AllowPublicKey(publicKeyAllowResponse(req.PublicKey)),
		}, nil
	} else if res.Allow.Value && !res.Deny.Value {
		// Allowed, no login needed.
		return []AuthMethodResult{
			AllowPublicKey(publicKeyAllowResponse(req.PublicKey)),
			AllowKeyboardInteractive(),
		}, nil
	} else {
		// Denied, no login needed.
		return []AuthMethodResult{
			DenyPublicKey(),
			DenyKeyboardInteractive(),
		}, nil
	}
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
			ValidBefore:           timestamppb.New(time.Now().Add(1 * time.Hour)),
			ValidAfter:            timestamppb.New(time.Now().Add(-1 * time.Minute)),
		},
	}
}

func (a *SSHAuth) HandleKeyboardInteractiveMethodRequest(
	ctx context.Context,
	info StreamAuthInfo,
	req *extensions_ssh.KeyboardInteractiveMethodRequest,
	querier KeyboardInteractiveQuerier,
) ([]AuthMethodResult, error) {
	// Initiate the IdP login flow.
	authenticator, err := a.getAuthenticator(ctx, info.Hostname)
	if err != nil {
		return nil, err
	}

	resp, err := authenticator.DeviceAuth(ctx)
	if err != nil {
		return nil, err
	}
	go querier.Prompt(ctx, &extensions_ssh.KeyboardInteractiveInfoPrompts{
		Name:        "Please sign in with " + authenticator.Name() + " to continue",
		Instruction: resp.VerificationURIComplete,
		Prompts:     nil,
	})

	var sessionClaims identity.SessionClaims
	token, err := authenticator.DeviceAccessToken(ctx, resp, &sessionClaims)
	if err != nil {
		return nil, err
	}
	version, err := a.saveSession(
		ctx, sessionIDFromFingerprint(info.PublicKeyFingerprintSha256), &sessionClaims, token)
	if err != nil {
		return nil, err
	}
	info.SessionRecordVersionHint = version

	// An empty hostname signals delayed authentication (route picker).
	if info.Hostname == "" {
		return []AuthMethodResult{AllowKeyboardInteractive()}, nil
	}

	// Otherwise evaluate access policy now.
	if err := a.EvaluateDelayed(ctx, info); err != nil {
		// Denied.
		return []AuthMethodResult{DenyKeyboardInteractive()}, err
	}
	// Allowed.
	return []AuthMethodResult{AllowKeyboardInteractive()}, nil
}

var errAccessDenied = errors.New("access denied")

func (a *SSHAuth) EvaluateDelayed(ctx context.Context, info StreamAuthInfo) error {
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

func (a *SSHAuth) FormatSession(ctx context.Context, info StreamAuthInfo) ([]byte, error) {
	sessionID := sessionIDFromFingerprint(info.PublicKeyFingerprintSha256)
	session, err := session.Get(ctx, a.dataBrokerClient, sessionID)
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

func (a *SSHAuth) DeleteSession(ctx context.Context, info StreamAuthInfo) error {
	sessionID := sessionIDFromFingerprint(info.PublicKeyFingerprintSha256)
	return session.Delete(ctx, a.dataBrokerClient, sessionID)
}

func (a *SSHAuth) saveSession(
	ctx context.Context,
	id string,
	claims *identity.SessionClaims,
	token *oauth2.Token,
) (uint64, error) {
	now := time.Now()
	nowpb := timestamppb.New(now)
	sessionLifetime := a.currentConfig.Load().Options.CookieExpire

	var state sessions.State
	claims.Claims.Claims(&state)

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

	u, _ := user.Get(ctx, a.dataBrokerClient, sess.GetUserId())
	if u == nil {
		// if no user exists yet, create a new one
		u = &user.User{
			Id: sess.GetUserId(),
		}
	}
	u.PopulateFromClaims(claims.Claims)
	_, err := databroker.Put(ctx, a.dataBrokerClient, u)
	if err != nil {
		return 0, err
	}

	resp, err := session.Put(ctx, a.dataBrokerClient, sess)
	if err != nil {
		return 0, err
	}
	return resp.GetRecord().Version, nil
}

func (a *SSHAuth) getAuthenticator(ctx context.Context, hostname string) (identity.Authenticator, error) {
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

var _ AuthInterface = (*SSHAuth)(nil)

func sessionIDFromFingerprint(sha256fingerprint []byte) string {
	return "sshkey-SHA256:" + base64.StdEncoding.EncodeToString(sha256fingerprint)
}

var errPublicKeyAllowNil = errors.New("expected PublicKeyAllow message not to be nil")

// Converts from StreamAuthInfo to an SSHRequest, assuming the PublicKeyAllow field is not nil.
func sshRequestFromStreamAuthInfo(info StreamAuthInfo) (*SSHRequest, error) {
	if info.PublicKeyAllow == nil {
		return nil, errPublicKeyAllowNil
	}

	return &SSHRequest{
		Username:                 info.Username,
		Hostname:                 info.Hostname,
		PublicKey:                info.PublicKeyAllow.PublicKey,
		SessionID:                sessionIDFromFingerprint(info.PublicKeyFingerprintSha256),
		SessionRecordVersionHint: info.SessionRecordVersionHint,
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
