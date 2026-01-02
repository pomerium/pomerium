package authenticate

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"

	"github.com/pomerium/pomerium/internal/handlers"
	"github.com/pomerium/pomerium/internal/httputil"
	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/internal/urlutil"
	"github.com/pomerium/pomerium/pkg/endpoints"
	"github.com/pomerium/pomerium/pkg/identity/oidc"
)

// SignOut signs the user out and attempts to revoke the user's identity session
// Handles both GET and POST.
func (a *Authenticate) SignOut(w http.ResponseWriter, r *http.Request) error {
	// check for an HMAC'd URL. If none is found, show a confirmation page.
	err := a.state.Load().flow.VerifyAuthenticateSignature(r)
	if err != nil {
		authenticateURL, err := a.options.Load().GetAuthenticateURL()
		if err != nil {
			return err
		}

		handlers.SignOutConfirm(handlers.SignOutConfirmData{
			URL:             urlutil.SignOutURL(r, authenticateURL, a.state.Load().sharedKey),
			BrandingOptions: a.options.Load().BrandingOptions,
		}).ServeHTTP(w, r)
		return nil
	}

	// otherwise actually do the sign out
	return a.signOutAndRedirect(w, r)
}

func (a *Authenticate) signOutAndRedirect(w http.ResponseWriter, r *http.Request) error {
	ctx, span := a.tracer.Start(r.Context(), "authenticate.SignOut")
	defer span.End()

	options := a.options.Load()
	idpID := a.getIdentityProviderIDForRequest(r)

	authenticator, err := a.cfg.getIdentityProvider(a.backgroundCtx, a.tracerProvider, options, idpID)
	if err != nil {
		return err
	}

	rawIDToken := a.revokeSession(ctx, w, r)

	authenticateURL, err := options.GetAuthenticateURL()
	if err != nil {
		return fmt.Errorf("error getting authenticate url: %w", err)
	}

	signOutRedirectURL, err := options.GetSignOutRedirectURL()
	if err != nil {
		return err
	}

	var signOutURL string
	if uri := r.FormValue(urlutil.QueryRedirectURI); uri != "" {
		signOutURL = uri
	} else if signOutRedirectURL != nil {
		signOutURL = signOutRedirectURL.String()
	}

	authenticateSignedOutURL := authenticateURL.ResolveReference(&url.URL{
		Path: endpoints.PathPomeriumSignedOut,
	}).String()

	if err := authenticator.SignOut(w, r, rawIDToken, authenticateSignedOutURL, signOutURL); err == nil {
		return nil
	} else if !errors.Is(err, oidc.ErrSignoutNotImplemented) {
		log.Ctx(r.Context()).Error().Err(err).Msg("authenticate: failed to get sign out url for authenticator")
	}

	// if the authenticator failed to sign out, and no sign out url is defined, just go to the signed out page
	if signOutURL == "" {
		signOutURL = authenticateSignedOutURL
	}

	httputil.Redirect(w, r, signOutURL, http.StatusFound)
	return nil
}

// revokeSession always clears the local session and tries to revoke the associated session stored in the
// databroker. If successful, it returns the original `id_token` of the session, if failed, returns
// and empty string.
func (a *Authenticate) revokeSession(ctx context.Context, w http.ResponseWriter, r *http.Request) string {
	state := a.state.Load()
	options := a.options.Load()

	// clear the user's local session no matter what
	defer state.sessionStore.ClearSession(w, r)

	idpID := r.FormValue(urlutil.QueryIdentityProviderID)

	authenticator, err := a.cfg.getIdentityProvider(a.backgroundCtx, a.tracerProvider, options, idpID)
	if err != nil {
		return ""
	}

	h, _ := a.getSessionHandleFromRequest(r)

	return state.flow.RevokeSession(ctx, r, authenticator, h)
}
