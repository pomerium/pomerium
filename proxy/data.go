package proxy

import (
	"context"
	"net/http"

	"github.com/pomerium/csrf"
	"github.com/pomerium/datasource/pkg/directory"
	"github.com/pomerium/pomerium/internal/encoding/jws"
	"github.com/pomerium/pomerium/internal/handlers"
	"github.com/pomerium/pomerium/internal/handlers/webauthn"
	"github.com/pomerium/pomerium/internal/httputil"
	"github.com/pomerium/pomerium/internal/sessions"
	"github.com/pomerium/pomerium/internal/urlutil"
	"github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/grpc/session"
	"github.com/pomerium/pomerium/pkg/grpc/user"
	"github.com/pomerium/pomerium/pkg/webauthnutil"
)

func (p *Proxy) getSession(ctx context.Context, sessionID string) (s *session.Session, isImpersonated bool, err error) {
	client := p.state.Load().dataBrokerClient

	isImpersonated = false
	s, err = session.Get(ctx, client, sessionID)
	if s.GetImpersonateSessionId() != "" {
		s, err = session.Get(ctx, client, s.GetImpersonateSessionId())
		isImpersonated = true
	}

	return s, isImpersonated, err
}

func (p *Proxy) getSessionState(r *http.Request) (sessions.State, error) {
	state := p.state.Load()

	rawJWT, err := state.sessionStore.LoadSession(r)
	if err != nil {
		return sessions.State{}, err
	}

	encoder, err := jws.NewHS256Signer(state.sharedKey)
	if err != nil {
		return sessions.State{}, err
	}

	var sessionState sessions.State
	if err := encoder.Unmarshal([]byte(rawJWT), &sessionState); err != nil {
		return sessions.State{}, httputil.NewError(http.StatusBadRequest, err)
	}

	return sessionState, nil
}

func (p *Proxy) getUser(ctx context.Context, userID string) (*user.User, error) {
	client := p.state.Load().dataBrokerClient
	return user.Get(ctx, client, userID)
}

func (p *Proxy) getUserInfoData(r *http.Request) (handlers.UserInfoData, error) {
	options := p.currentOptions.Load()
	state := p.state.Load()

	data := handlers.UserInfoData{
		CSRFToken:       csrf.Token(r),
		BrandingOptions: options.BrandingOptions,
	}

	ss, err := p.getSessionState(r)
	if err != nil {
		return handlers.UserInfoData{}, err
	}

	data.Session, data.IsImpersonated, err = p.getSession(r.Context(), ss.ID)
	if err != nil {
		data.Session = &session.Session{Id: ss.ID}
	}

	data.User, err = p.getUser(r.Context(), data.Session.GetUserId())
	if err != nil {
		data.User = &user.User{Id: data.Session.GetUserId()}
	}

	data.WebAuthnCreationOptions, data.WebAuthnRequestOptions, _ = p.webauthn.GetOptions(r)
	data.WebAuthnURL = urlutil.WebAuthnURL(r, urlutil.GetAbsoluteURL(r), state.sharedKey, r.URL.Query())
	p.fillEnterpriseUserInfoData(r.Context(), &data)
	return data, nil
}

func (p *Proxy) fillEnterpriseUserInfoData(ctx context.Context, data *handlers.UserInfoData) {
	client := p.state.Load().dataBrokerClient

	res, _ := client.Get(ctx, &databroker.GetRequest{Type: "type.googleapis.com/pomerium.config.Config", Id: "dashboard"})
	data.IsEnterprise = res.GetRecord() != nil
	if !data.IsEnterprise {
		return
	}

	data.DirectoryUser, _ = databroker.GetViaJSON[directory.User](ctx, client, directory.UserRecordType, data.Session.GetUserId())
	if data.DirectoryUser != nil {
		for _, groupID := range data.DirectoryUser.GroupIDs {
			directoryGroup, _ := databroker.GetViaJSON[directory.Group](ctx, client, directory.GroupRecordType, groupID)
			if directoryGroup != nil {
				data.DirectoryGroups = append(data.DirectoryGroups, directoryGroup)
			}
		}
	}
}

func (p *Proxy) getWebauthnState(r *http.Request) (*webauthn.State, error) {
	options := p.currentOptions.Load()
	state := p.state.Load()

	ss, err := p.getSessionState(r)
	if err != nil {
		return nil, err
	}

	s, _, err := p.getSession(r.Context(), ss.ID)
	if err != nil {
		return nil, err
	}

	authenticateURL, err := options.GetAuthenticateURL()
	if err != nil {
		return nil, err
	}

	internalAuthenticateURL, err := options.GetInternalAuthenticateURL()
	if err != nil {
		return nil, err
	}

	pomeriumDomains, err := options.GetAllRouteableHTTPDomains()
	if err != nil {
		return nil, err
	}

	return &webauthn.State{
		AuthenticateURL:         authenticateURL,
		InternalAuthenticateURL: internalAuthenticateURL,
		SharedKey:               state.sharedKey,
		Client:                  state.dataBrokerClient,
		PomeriumDomains:         pomeriumDomains,
		Session:                 s,
		SessionState:            &ss,
		SessionStore:            state.sessionStore,
		RelyingParty:            webauthnutil.GetRelyingParty(r, state.dataBrokerClient),
		BrandingOptions:         options.BrandingOptions,
	}, nil
}
