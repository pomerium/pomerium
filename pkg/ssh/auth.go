package ssh

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"slices"
	"sync/atomic"
	"time"

	oteltrace "go.opentelemetry.io/otel/trace"
	"golang.org/x/oauth2"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	extensions_ssh "github.com/pomerium/envoy-custom/api/extensions/filters/network/ssh"
	"github.com/pomerium/pomerium/authorize/evaluator"
	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/internal/sessions"
	"github.com/pomerium/pomerium/pkg/grpc/databroker"
	identitypb "github.com/pomerium/pomerium/pkg/grpc/identity"
	"github.com/pomerium/pomerium/pkg/grpc/session"
	"github.com/pomerium/pomerium/pkg/grpc/user"
	"github.com/pomerium/pomerium/pkg/identity"
	"github.com/pomerium/pomerium/pkg/identity/manager"
	"github.com/pomerium/pomerium/pkg/policy/criteria"
	"github.com/pomerium/pomerium/pkg/ssh/pending"
)

type Evaluator interface {
	EvaluateSSH(ctx context.Context, streamID uint64, req *Request) (*evaluator.Result, error)
	GetDataBrokerServiceClient() databroker.DataBrokerServiceClient
	InvalidateCacheForRecords(context.Context, ...*databroker.Record)
}

type Request struct {
	Username      string
	Hostname      string
	PublicKey     []byte
	SessionID     string
	SourceAddress string

	LogOnlyIfDenied bool
}

type Auth struct {
	evaluator      Evaluator
	currentConfig  *atomic.Pointer[config.Config]
	tracerProvider oteltrace.TracerProvider
	codeIssuer     pending.CodeIssuer
}

func NewAuth(
	ctx context.Context,
	evaluator Evaluator,
	currentConfig *atomic.Pointer[config.Config],
	tracerProvider oteltrace.TracerProvider,
) *Auth {
	codeIssuer := pending.NewDistributedCodeIssuer(ctx, evaluator.GetDataBrokerServiceClient())
	return &Auth{
		evaluator,
		currentConfig,
		tracerProvider,
		codeIssuer,
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
	sessionID, err := a.resolveSessionIDFromFingerprint(ctx, req.PublicKeyFingerprintSha256)
	if err != nil {
		if !databroker.IsNotFound(err) {
			return PublicKeyAuthMethodResponse{}, err
		}
	}
	sshreq := &Request{
		Username:      *info.Username,
		Hostname:      *info.Hostname,
		PublicKey:     req.PublicKey,
		SessionID:     sessionID,
		SourceAddress: info.SourceAddress,
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

	res, err := a.evaluator.EvaluateSSH(ctx, info.StreamID, sshreq)
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
	err := a.handleLogin(ctx, *info.Hostname, info.SourceAddress, info.PublicKeyFingerprintSha256, querier)
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
	sourceAddr string,
	publicKeyFingerprint []byte,
	querier KeyboardInteractiveQuerier,
) error {
	bindingKey, err := sessionIDFromFingerprint(publicKeyFingerprint)
	if err != nil {
		return err
	}
	idp, authenticator, err := a.getAuthenticator(ctx, hostname)
	if err != nil {
		return err
	}
	cfg := a.currentConfig.Load()
	authUrl, _ := cfg.Options.GetInternalAuthenticateURL()
	generatedCode := a.codeIssuer.IssueCode()
	now := timestamppb.Now()

	req := &session.SessionBindingRequest{
		IdpId:     idp.GetId(),
		Key:       bindingKey,
		Protocol:  session.ProtocolSSH,
		CreatedAt: now,
		ExpiresAt: timestamppb.New(now.AsTime().Add(1 * time.Minute)), // XXX
		Details: map[string]string{
			session.DetailSourceAddr: sourceAddr,
		},
	}

	// * Gets an existing code if it exists and is valid
	// * Stores a new code atomically if there are no valid codes

	// * 1. Lease per sessionID
	// * 2. Strongly eventual consistent sync -> compare latest record type to seen record type
	// * 3. Atomic CompareAndSwap() directly on the storage layer
	associatedCode, err := a.codeIssuer.AssociateCode(ctx, generatedCode, req)
	if err != nil {
		return status.Error(codes.Aborted, "failed to associate a code to this session")
	}
	var prompt string

	if generatedCode == associatedCode {
		query := &url.Values{}
		query.Add("user_code", string(generatedCode))
		promptURI := authUrl.ResolveReference(&url.URL{
			Path:     "/.pomerium/sign_in",
			RawQuery: query.Encode(),
		})
		prompt = promptURI.String()
	} else {
		prompt = "Sign in initiated from another session. Waiting..."
	}
	_, _ = querier.Prompt(ctx, &extensions_ssh.KeyboardInteractiveInfoPrompts{
		Name:        "Please sign in with " + authenticator.Name() + " to continue",
		Instruction: prompt,
		Prompts:     nil,
	})

	invalidC := a.codeIssuer.OnCodeInvalid(ctx, pending.SessionID(bindingKey), associatedCode)
	successC := a.codeIssuer.OnCodeSuccess(ctx, pending.SessionID(bindingKey))

	select {
	case <-a.codeIssuer.Done():
		return status.Error(codes.Internal, "code issuer can no longer process this request")
	case <-ctx.Done():
		if generatedCode == associatedCode {
			// * stream has ended, and we own this code so we must revoke it.
			slog.Default().Info("revoking code since we own it")
			ctxca, ca := context.WithTimeout(context.Background(), time.Second*30)
			defer ca()
			err := a.codeIssuer.RevokeCode(ctxca, generatedCode)
			if err != nil {
				slog.Default().With("err", err).Error("failed to revoke code")
			}
		}
		return status.Error(codes.Canceled, "authentication request cancelled by user")
	case err := <-invalidC:
		return status.Error(codes.Canceled, err.Error())
	case records, ok := <-successC:
		if !ok {
			return status.Error(codes.Canceled, "failed to receive successful authentication request")
		}
		a.evaluator.InvalidateCacheForRecords(ctx, records...)
		return nil
	}
}

var errAccessDenied = status.Error(codes.PermissionDenied, "access denied")

func (a *Auth) EvaluateDelayed(ctx context.Context, info StreamAuthInfo) error {
	req, err := a.sshRequestFromStreamAuthInfo(ctx, info)
	if err != nil {
		return err
	}
	res, err := a.evaluator.EvaluateSSH(ctx, info.StreamID, req)
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
	err = session.Delete(ctx, a.evaluator.GetDataBrokerServiceClient(), sessionID)
	a.evaluator.InvalidateCacheForRecords(ctx, &databroker.Record{
		Type: "type.googleapis.com/session.Session",
		Id:   sessionID,
	})
	return err
}

func (a *Auth) saveSession(
	ctx context.Context,
	idpID,
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

	sess := session.New(idpID, id)
	sess.UserId = state.UserID()
	sess.IssuedAt = nowpb
	sess.AccessedAt = nowpb
	sess.ExpiresAt = timestamppb.New(now.Add(sessionLifetime))
	sess.OauthToken = manager.ToOAuthToken(token)
	sess.Audience = state.Audience
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
	a.evaluator.InvalidateCacheForRecords(ctx, resp.GetRecord())

	resp, err = session.Put(ctx, a.evaluator.GetDataBrokerServiceClient(), sess)
	if err != nil {
		return err
	}
	a.evaluator.InvalidateCacheForRecords(ctx, resp.GetRecord())
	return nil
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
		return "", errors.New("not found")
	}
	var binding session.SessionBinding
	if err := resp.Record.Data.UnmarshalTo(&binding); err != nil {
		return "", err
	}
	// TODO check timestamps
	if binding.Protocol != "ssh" {
		return "", errors.New("invalid protocol")
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
func (a *Auth) sshRequestFromStreamAuthInfo(ctx context.Context, info StreamAuthInfo) (*Request, error) {
	if info.PublicKeyAllow.Value == nil {
		return nil, errPublicKeyAllowNil
	}
	sessionID, err := a.resolveSessionIDFromFingerprint(ctx, info.PublicKeyFingerprintSha256)
	if err != nil {
		return nil, err
	}

	return &Request{
		Username:      *info.Username,
		Hostname:      *info.Hostname,
		PublicKey:     info.PublicKeyAllow.Value.PublicKey,
		SessionID:     sessionID,
		SourceAddress: info.SourceAddress,

		LogOnlyIfDenied: info.InitialAuthComplete,
	}, nil
}
