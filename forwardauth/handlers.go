package forwardauth

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/url"

	"github.com/pomerium/pomerium/internal/httputil"
	"github.com/pomerium/pomerium/internal/sessions"
	"github.com/pomerium/pomerium/internal/urlutil"
	"github.com/pomerium/pomerium/pkg/cryptutil"
)

// saveCallbackSession takes an encrypted per-route session token, and decrypts
// it using the shared service key, then stores it the local session store.
func (fa *ForwardAuth) saveCallbackSession(w http.ResponseWriter, r *http.Request, enctoken string) ([]byte, error) {
	state := fa.state.Load()

	// 1. extract the base64 encoded and encrypted JWT from query params
	encryptedJWT, err := base64.URLEncoding.DecodeString(enctoken)
	if err != nil {
		return nil, fmt.Errorf("fowardauth: malfromed callback token: %w", err)
	}
	// 2. decrypt the JWT using the cipher using the _shared_ secret key
	rawJWT, err := cryptutil.Decrypt(state.sharedCipher, encryptedJWT, nil)
	if err != nil {
		return nil, fmt.Errorf("fowardauth: callback token decrypt error: %w", err)
	}
	// 3. Save the decrypted JWT to the session store directly as a string, without resigning
	if err = state.sessionStore.SaveSession(w, r, rawJWT); err != nil {
		return nil, fmt.Errorf("fowardauth: callback session save failure: %w", err)
	}
	return rawJWT, nil
}

// registerFwdAuthHandlers returns a set of handlers that support using pomerium
// as a "forward-auth" provider with other reverse proxies like nginx, traefik.
//
// see : https://www.pomerium.io/configuration/#forward-auth
func (fa *ForwardAuth) registerFwdAuthHandlers() http.Handler {
	r := httputil.NewRouter()
	r.StrictSlash(true)
	r.Use(func(h http.Handler) http.Handler {
		return sessions.RetrieveSession(fa.state.Load().sessionStore)(h)
	})
	r.Use(fa.jwtClaimMiddleware)

	// NGNIX's forward-auth capabilities are split across two settings:
	// `auth-url` and `auth-signin` which correspond to `verify` and `auth-url`
	//
	// NOTE: Route order matters here which makes the request flow confusing
	// 		 to reason about so each step has a postfix order step.

	// nginx 3: save the returned session post authenticate flow
	r.Handle("/verify", httputil.HandlerFunc(fa.nginxCallback)).
		Queries("uri", "{uri}", urlutil.QuerySessionEncrypted, "", urlutil.QueryRedirectURI, "")

	// nginx 1: verify. Return 401 if invalid and NGINX will call `auth-signin`
	r.Handle("/verify", fa.Verify(true)).Queries("uri", "{uri}")

	// nginx 4: redirect the user back to their originally requested location.
	r.Handle("/", httputil.HandlerFunc(fa.nginxPostCallbackRedirect)).
		Queries("uri", "{uri}", urlutil.QuerySessionEncrypted, "", urlutil.QueryRedirectURI, "")

	// traefik 2: save the returned session post authenticate flow
	r.Handle("/", httputil.HandlerFunc(fa.forwardedURIHeaderCallback)).
		HeadersRegexp(httputil.HeaderForwardedURI, urlutil.QuerySessionEncrypted)

	// nginx 2 / traefik 1: verify and then start authenticate flow
	r.Handle("/", fa.Verify(false))

	return r
}

// nginxPostCallbackRedirect redirects the user to their original destination
// in order to drop the authenticate related query params
func (fa *ForwardAuth) nginxPostCallbackRedirect(w http.ResponseWriter, r *http.Request) error {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	httputil.Redirect(w, r, r.FormValue(urlutil.QueryRedirectURI), http.StatusFound)
	return nil
}

// nginxCallback saves the returned session post callback and then returns an
// unauthorized status in order to restart the request flow process. Strangely
// we need to throw a 401 after saving the session to redirect the user
// to their originally desired location.
func (fa *ForwardAuth) nginxCallback(w http.ResponseWriter, r *http.Request) error {
	encryptedSession := r.FormValue(urlutil.QuerySessionEncrypted)
	if _, err := fa.saveCallbackSession(w, r, encryptedSession); err != nil {
		return httputil.NewError(http.StatusBadRequest, err)
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusUnauthorized)
	return nil
}

// forwardedURIHeaderCallback handles the post-authentication callback from
// forwarding proxies that support the `X-Forwarded-Uri`.
func (fa *ForwardAuth) forwardedURIHeaderCallback(w http.ResponseWriter, r *http.Request) error {
	forwardedURL, err := url.Parse(r.Header.Get(httputil.HeaderForwardedURI))
	if err != nil {
		return httputil.NewError(http.StatusBadRequest, err)
	}
	q := forwardedURL.Query()
	redirectURLString := q.Get(urlutil.QueryRedirectURI)
	encryptedSession := q.Get(urlutil.QuerySessionEncrypted)

	if _, err := fa.saveCallbackSession(w, r, encryptedSession); err != nil {
		return httputil.NewError(http.StatusBadRequest, err)
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	httputil.Redirect(w, r, redirectURLString, http.StatusFound)
	return nil
}

// Verify checks a user's credentials for an arbitrary host. If the user
// is properly authenticated and is authorized to access the supplied host,
// a `200` http status code is returned. If the user is not authenticated, they
// will be redirected to the authenticate service to sign in with their identity
// provider. If the user is unauthorized, a `401` error is returned.
func (fa *ForwardAuth) Verify(verifyOnly bool) http.Handler {
	return httputil.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		state := fa.state.Load()

		var err error
		if status := r.FormValue("auth_status"); status == fmt.Sprint(http.StatusForbidden) {
			return httputil.NewError(http.StatusForbidden, errors.New(http.StatusText(http.StatusForbidden)))
		}

		uri, err := getURIStringFromRequest(r)
		if err != nil {
			return httputil.NewError(http.StatusBadRequest, err)
		}

		ar, err := fa.isAuthorized(w, r)
		if err != nil {
			return httputil.NewError(http.StatusBadRequest, err)
		}

		if ar.authorized {
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			w.WriteHeader(http.StatusOK)
			fmt.Fprintf(w, "Access to %s is allowed.", uri.Host)
			return nil
		}

		unAuthenticated := ar.statusCode == http.StatusUnauthorized
		if unAuthenticated {
			state.sessionStore.ClearSession(w, r)
		}

		_, err = sessions.FromContext(r.Context())
		hasSession := err == nil
		if hasSession && !unAuthenticated {
			return httputil.NewError(http.StatusForbidden, errors.New("access denied"))
		}

		if verifyOnly {
			return httputil.NewError(http.StatusUnauthorized, err)
		}

		fa.forwardAuthRedirectToSignInWithURI(w, r, uri)
		return nil
	})
}

// forwardAuthRedirectToSignInWithURI redirects request to authenticate signin url,
// with all necessary information extracted from given input uri.
func (fa *ForwardAuth) forwardAuthRedirectToSignInWithURI(w http.ResponseWriter, r *http.Request, uri *url.URL) {
	state := fa.state.Load()

	// Traefik set the uri in the header, we must set it in redirect uri if present. Otherwise, request like
	// https://example.com/foo will be redirected to https://example.com after authentication.
	if xfu := r.Header.Get(httputil.HeaderForwardedURI); xfu != "/" {
		uri.Path = xfu
	}

	// redirect to authenticate
	authN := *state.authenticateSigninURL
	q := authN.Query()
	q.Set(urlutil.QueryCallbackURI, uri.String())
	q.Set(urlutil.QueryRedirectURI, uri.String())              // final destination
	q.Set(urlutil.QueryForwardAuth, urlutil.StripPort(r.Host)) // add fwd auth to trusted audience
	authN.RawQuery = q.Encode()
	httputil.Redirect(w, r, urlutil.NewSignedURL(state.sharedKey, &authN).String(), http.StatusFound)
}

func getURIStringFromRequest(r *http.Request) (*url.URL, error) {
	// the route to validate will be pulled from the uri queryparam
	// or inferred from forwarding headers
	uriString := r.FormValue("uri")
	if uriString == "" {
		if r.Header.Get(httputil.HeaderForwardedProto) == "" || r.Header.Get(httputil.HeaderForwardedHost) == "" {
			return nil, errors.New("no uri to validate")
		}
		uriString = r.Header.Get(httputil.HeaderForwardedProto) + "://" +
			r.Header.Get(httputil.HeaderForwardedHost) +
			r.Header.Get(httputil.HeaderForwardedURI)
	}

	uri, err := urlutil.ParseAndValidateURL(uriString)
	if err != nil {
		return nil, err
	}
	return uri, nil
}
