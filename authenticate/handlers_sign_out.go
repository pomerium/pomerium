package authenticate

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/pomerium/pomerium/internal/handlers"
	"github.com/pomerium/pomerium/internal/httputil"
	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/internal/urlutil"
	"github.com/pomerium/pomerium/pkg/endpoints"
	"github.com/pomerium/pomerium/pkg/identity"
	"github.com/pomerium/pomerium/pkg/identity/oidc"
	"github.com/pomerium/pomerium/pkg/identity/oidc/hosted"
)

// SignOut signs the user out and attempts to revoke the user's identity session
// Handles both GET and POST.
func (a *Authenticate) SignOut(w http.ResponseWriter, r *http.Request) error {
	// check for an HMAC'd URL. If none is found, show a confirmation page,
	// except if we are using the hosted-authenticate OIDC flow (in which
	// case the hosted-authenticate service will show its own prompt).
	isHostedAuthenticateOIDC := a.options.Load().Provider == hosted.Name

	options := a.options.Load()
	idpID := a.getIdentityProviderIDForRequest(r)
	authenticator, getErr := a.cfg.getIdentityProvider(a.backgroundCtx, a.tracerProvider, options, idpID)
	if getErr != nil {
		return getErr
	}

	err := a.state.Load().flow.VerifyAuthenticateSignature(r)
	if err != nil && !isHostedAuthenticateOIDC {
		authenticateURL, err := a.options.Load().GetAuthenticateURL()
		if err != nil {
			return err
		}

		handlers.SignOutConfirm(handlers.SignOutConfirmData{
			URL:             urlutil.SignOutURL(r, authenticateURL, a.state.Load().sharedKey),
			BrandingOptions: a.options.Load().BrandingOptions,
			ReAuthEnabled:   authenticator.ReAuthSupport() == identity.ReAuthenticationEnabled,
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
	state := a.state.Load()
	idpID := a.getIdentityProviderIDForRequest(r)

	authenticator, err := a.cfg.getIdentityProvider(a.backgroundCtx, a.tracerProvider, options, idpID)
	if err != nil {
		return err
	}

	// | invalidates the current browsers session
	h, _ := a.getSessionHandleFromRequest(r)
	// clear the user's local session no matter what
	defer state.sessionHandleWriter.ClearSessionHandle(w)
	rawIDToken := state.flow.RevokeSession(ctx, r, nil, h)
	// |

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

	allDevices := r.FormValue("allDevices") != ""
	// if logging out from a browser, must revoke the idpsession unless the IDP supports ReAuth.
	if !allDevices && authenticator.ReAuthSupport() != identity.ReAuthenticationEnabled {
		return httputil.NewError(http.StatusBadRequest, fmt.Errorf("bad request"))
	}

	if allDevices {
		if err := state.flow.RevokeUserSession(ctx, h, authenticator); err != nil {
			log.Ctx(ctx).Err(err).Msg("failed to revoke user session")
		}
		if err := a.fullLogout(w, r, rawIDToken, authenticator, authenticateSignedOutURL, signOutURL); err == nil {
			return nil
		} else if !errors.Is(err, oidc.ErrSignoutNotImplemented) {
			log.Ctx(r.Context()).Error().Err(err).Msg("authenticate: failed to get sign out url for authenticator")
		}
	}

	if signOutURL == "" {
		httputil.Redirect(w, r, authenticateSignedOutURL, http.StatusFound)
		return nil
	}

	httputil.Redirect(w, r, signOutURL, http.StatusFound)
	return nil
}

func (a *Authenticate) fullLogout(
	w http.ResponseWriter,
	r *http.Request,
	rawIDToken string,
	authenticator identity.Authenticator,
	authenticateSignedOutURL, signOutURL string,
) error {
	// FIXME: debug
	_ = os.WriteFile("signout-"+time.Now().Format(time.RFC3339)+".json", []byte("{\"raw_id_token\":\""+rawIDToken+"\"}"), 0o600)
	if err := authenticator.SignOut(w, r, rawIDToken, authenticateSignedOutURL, signOutURL); err == nil {
		return nil
	} else if !errors.Is(err, oidc.ErrSignoutNotImplemented) {
		log.Ctx(r.Context()).Error().Err(err).Msg("authenticate: failed to get sign out url for authenticator")
	}
	return nil
}
