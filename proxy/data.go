package proxy

import (
	"context"
	"net/http"

	"github.com/pomerium/datasource/pkg/directory"
	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/handlers"
	"github.com/pomerium/pomerium/internal/handlers/webauthn"
	"github.com/pomerium/pomerium/internal/urlutil"
	"github.com/pomerium/pomerium/pkg/grpc/session"
	"github.com/pomerium/pomerium/pkg/grpc/user"
	"github.com/pomerium/pomerium/pkg/storage"
	"github.com/pomerium/pomerium/pkg/webauthnutil"
)

func (p *Proxy) getSession(ctx context.Context, sessionID string) (s *session.Session, isImpersonated bool, err error) {
	isImpersonated = false
	s, err = storage.GetDataBrokerMessage[session.Session](ctx, sessionID, 0)
	if s.GetImpersonateSessionId() != "" {
		s, err = storage.GetDataBrokerMessage[session.Session](ctx, s.GetImpersonateSessionId(), 0)
		isImpersonated = true
	}
	return s, isImpersonated, err
}

func (p *Proxy) getUser(ctx context.Context, userID string) (*user.User, error) {
	return storage.GetDataBrokerMessage[user.User](ctx, userID, 0)
}

func (p *Proxy) getUserInfoData(r *http.Request) handlers.UserInfoData {
	cfg := p.currentConfig.Load()
	state := p.state.Load()

	data := handlers.UserInfoData{
		BrandingOptions: cfg.Options.BrandingOptions,
	}

	if s, err := state.incomingIDPTokenSessionCreator.CreateSession(r.Context(), cfg, nil, r); err == nil {
		data.Session = s
		data.IsImpersonated = false

		data.User, err = p.getUser(r.Context(), data.Session.GetUserId())
		if err != nil {
			data.User = &user.User{Id: data.Session.GetUserId()}
		}
	}

	ss, err := p.state.Load().sessionStore.LoadSessionHandle(r)
	if err == nil {
		data.Session, data.IsImpersonated, err = p.getSession(r.Context(), ss.ID)
		if err != nil {
			data.Session = session.New(ss.IdentityProviderID, ss.ID)
		}

		data.User, err = p.getUser(r.Context(), data.Session.GetUserId())
		if err != nil {
			data.User = &user.User{Id: data.Session.GetUserId()}
		}
	}

	if creationOptions, requestOptions, err := p.webauthn.GetOptions(r); err == nil {
		data.WebAuthnCreationOptions = creationOptions
		data.WebAuthnRequestOptions = requestOptions
		data.WebAuthnURL = urlutil.WebAuthnURL(r, urlutil.GetAbsoluteURL(r), state.sharedKey, r.URL.Query())
	}
	data.RuntimeFlags = map[string]bool{
		"routes_portal":        cfg.Options.IsRuntimeFlagSet(config.RuntimeFlagRoutesPortal),
		"is_hosted_data_plane": cfg.Options.UseStatelessAuthenticateFlow(),
	}
	p.fillEnterpriseUserInfoData(r.Context(), &data)
	return data
}

func (p *Proxy) fillEnterpriseUserInfoData(ctx context.Context, data *handlers.UserInfoData) {
	record, _ := storage.GetDataBrokerRecord(ctx, "type.googleapis.com/pomerium.config.Config", "dashboard-settings", 0)
	data.IsEnterprise = record != nil
	if !data.IsEnterprise {
		return
	}

	data.DirectoryUser, _ = storage.GetDataBrokerObjectViaJSON[directory.User](ctx, directory.UserRecordType, data.Session.GetUserId(), 0)
	if data.DirectoryUser != nil {
		for _, groupID := range data.DirectoryUser.GroupIDs {
			directoryGroup, _ := storage.GetDataBrokerObjectViaJSON[directory.Group](ctx, directory.GroupRecordType, groupID, 0)
			if directoryGroup != nil {
				data.DirectoryGroups = append(data.DirectoryGroups, directoryGroup)
			}
		}
	}
}

func (p *Proxy) getWebauthnState(r *http.Request) (*webauthn.State, error) {
	options := p.currentConfig.Load().Options
	state := p.state.Load()

	ss, err := p.state.Load().sessionStore.LoadSessionHandle(r)
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

	return &webauthn.State{
		AuthenticateURL:         authenticateURL,
		InternalAuthenticateURL: internalAuthenticateURL,
		SharedKey:               state.sharedKey,
		Client:                  state.dataBrokerClient,
		Session:                 s,
		SessionHandle:           ss,
		SessionStore:            state.sessionStore,
		RelyingParty:            webauthnutil.GetRelyingParty(r, state.dataBrokerClient),
		BrandingOptions:         options.BrandingOptions,
	}, nil
}
