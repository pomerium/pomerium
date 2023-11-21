package authenticateflow

import (
	"context"
	"net/http"
	"net/url"

	"github.com/pomerium/pomerium/internal/httputil"
	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/internal/urlutil"
	identitypb "github.com/pomerium/pomerium/pkg/grpc/identity"
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
	// Email is the email of the user
	Email *string
	// Domain is the domain of the request (for sign in complete events)
	Domain *string
}

// AuthEventFn is a function that handles an authentication event
type AuthEventFn func(context.Context, AuthEvent)

// TODO: move into stateless.go; this is here for now just so that Git will
// track the file history as a rename from authenticate/events.go.
func (s *Stateless) logAuthenticateEvent(r *http.Request, profile *identitypb.Profile) {
	if s.authEventFn == nil {
		return
	}

	ctx := r.Context()
	pub, params, err := hpke.DecryptURLValues(s.hpkePrivateKey, r.Form)
	if err != nil {
		log.Warn(ctx).Err(err).Msg("log authenticate event: failed to decrypt request params")
	}

	evt := AuthEvent{
		IP:          httputil.GetClientIP(r),
		Version:     params.Get(urlutil.QueryVersion),
		RequestUUID: params.Get(urlutil.QueryRequestUUID),
		PubKey:      pub.String(),
	}

	if uid := getUserClaim(profile, "sub"); uid != nil {
		evt.UID = uid
	}
	if email := getUserClaim(profile, "email"); email != nil {
		evt.Email = email
	}

	if evt.UID != nil {
		evt.Event = AuthEventSignInComplete
	} else {
		evt.Event = AuthEventSignInRequest
	}

	if redirectURL, err := url.Parse(params.Get(urlutil.QueryRedirectURI)); err == nil {
		domain := redirectURL.Hostname()
		evt.Domain = &domain
	}

	s.authEventFn(ctx, evt)
}
