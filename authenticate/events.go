package authenticate

import (
	"context"
	"net/http"
	"net/url"

	"github.com/pomerium/pomerium/internal/httputil"
	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/internal/urlutil"
	"github.com/pomerium/pomerium/pkg/grpc/identity"
	"github.com/pomerium/pomerium/pkg/hpke"
)

// AuthEventKind is the type of an authentication event
type AuthEventKind string

const (
	// AuthEventSignInRequest is an authentication event for a sign in request before IdP redirect
	AuthEventSignInRequest AuthEventKind = "sign_in_request"
	// AuthEventSignInComplete is an authentication event for a sign in request after IdP redirect
	AuthEventSignInComplete AuthEventKind = "sign_in_complete"
)

// AuthEvent is a log event for an authentication event
type AuthEvent struct {
	// Event is the type of authentication event
	Event AuthEventKind
	// IP is the IP address of the client
	IP string
	// Version is the version of the Pomerium client
	Version string
	// RequestUUID is the UUID of the request
	RequestUUID string
	// PubKey is the public key of the client
	PubKey string
	// UID is the IdP user ID of the user
	UID *string
	// Domain is the domain of the request (for sign in complete events)
	Domain *string
}

// AuthEventFn is a function that handles an authentication event
type AuthEventFn func(context.Context, AuthEvent)

func (a *Authenticate) logAuthenticateEvent(r *http.Request, profile *identity.Profile) {
	state := a.state.Load()
	ctx := r.Context()
	pub, params, err := hpke.DecryptURLValues(state.hpkePrivateKey, r.Form)
	if err != nil {
		log.Warn(ctx).Err(err).Msg("log authenticate event: failed to decrypt request params")
	}

	evt := AuthEvent{
		IP:          httputil.GetClientIP(r),
		Version:     params.Get(urlutil.QueryVersion),
		RequestUUID: params.Get(urlutil.QueryRequestUUID),
		PubKey:      pub.String(),
	}

	if uid := getUserID(profile); uid != "" {
		uid := getUserID(profile)
		evt.UID = &uid
		evt.Event = AuthEventSignInComplete
	} else {
		evt.Event = AuthEventSignInRequest
	}

	if redirectURL, err := url.Parse(params.Get(urlutil.QueryRedirectURI)); err == nil {
		domain := redirectURL.Hostname()
		evt.Domain = &domain
	}

	if a.cfg.authEventFn != nil {
		a.cfg.authEventFn(ctx, evt)
	}
}

func getUserID(profile *identity.Profile) string {
	if profile == nil {
		return ""
	}
	if profile.Claims == nil {
		return ""
	}
	return profile.Claims.Fields["sub"].GetStringValue()
}
