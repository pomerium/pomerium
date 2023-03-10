package authenticate

import (
	"context"
	"net/http"
	"net/url"

	"github.com/pomerium/pomerium/internal/httputil"
	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/internal/middleware"
	"github.com/pomerium/pomerium/internal/urlutil"
	"github.com/pomerium/pomerium/pkg/grpc/identity"
	"github.com/pomerium/pomerium/pkg/hpke"
)

// requireValidSignatureOnRedirect validates the pomerium_signature if a redirect_uri or pomerium_signature
// is present on the query string.
func (a *Authenticate) requireValidSignatureOnRedirect(next httputil.HandlerFunc) http.Handler {
	return httputil.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		if r.FormValue(urlutil.QueryRedirectURI) != "" || r.FormValue(urlutil.QueryHmacSignature) != "" {
			err := middleware.ValidateRequestURL(a.getExternalRequest(r), a.state.Load().sharedKey)
			if err != nil {
				return httputil.NewError(http.StatusBadRequest, err)
			}
		}
		return next(w, r)
	})
}

// requireValidSignature validates the pomerium_signature.
func (a *Authenticate) requireValidSignature(next httputil.HandlerFunc) http.Handler {
	return httputil.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		err := middleware.ValidateRequestURL(a.getExternalRequest(r), a.state.Load().sharedKey)
		if err != nil {
			return err
		}
		return next(w, r)
	})
}

func (a *Authenticate) getExternalRequest(r *http.Request) *http.Request {
	options := a.options.Load()

	externalURL, err := options.GetAuthenticateURL()
	if err != nil {
		return r
	}

	internalURL, err := options.GetInternalAuthenticateURL()
	if err != nil {
		return r
	}

	return urlutil.GetExternalRequest(internalURL, externalURL, r)
}

func (a *Authenticate) logAuthenticateEvent(r *http.Request, profile *identity.Profile) {
	state := a.state.Load()
	ctx := r.Context()
	pub, params, err := hpke.DecryptURLValues(state.hpkePrivateKey, r.Form)
	if err != nil {
		log.Warn(ctx).Err(err).Msg("log authenticate event: failed to decrypt request params")
	}

	evt := log.Info(context.Background()).
		Str("ip", httputil.GetClientIP(r)).
		Str("pomerium_version", params.Get(urlutil.QueryVersion)).
		Str("pomerium_request_uuid", params.Get(urlutil.QueryRequestUUID)).
		Str("pomerium_pub", pub.String())

	if uid := getUserID(profile); uid != "" {
		evt = evt.Str("authenticate_event", "sign_in_completed").
			Str("pomerium_idp_user", getUserID(profile))
	} else {
		evt = evt.Str("authenticate_event", "sign_in")
	}

	if redirectURL, err := url.Parse(params.Get(urlutil.QueryRedirectURI)); err == nil {
		evt = evt.Str("domain", redirectURL.Hostname())
	}

	evt.Msg("authenticate: event")
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
