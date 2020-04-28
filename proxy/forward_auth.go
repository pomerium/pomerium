package proxy

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"

	"github.com/pomerium/pomerium/internal/httputil"
	"github.com/pomerium/pomerium/internal/sessions"
	"github.com/pomerium/pomerium/internal/urlutil"
)

// registerFwdAuthHandlers returns a set of handlers that support using pomerium
// as a "forward-auth" provider with other reverse proxies like nginx, traefik.
//
// see : https://www.pomerium.io/configuration/#forward-auth
func (p *Proxy) registerFwdAuthHandlers() http.Handler {
	r := httputil.NewRouter()
	r.StrictSlash(true)
	r.Use(sessions.RetrieveSession(p.sessionStore))

	// NGNIX's forward-auth capabilities are split across two settings:
	// `auth-url` and `auth-signin` which correspond to `verify` and `auth-url`
	//
	// NOTE: Route order matters here which makes the request flow confusing
	// 		 to reason about so each step has a postfix order step.

	// nginx 3: save the returned session post authenticate flow
	r.Handle("/verify", httputil.HandlerFunc(p.nginxCallback)).
		Queries("uri", "{uri}", urlutil.QuerySessionEncrypted, "", urlutil.QueryRedirectURI, "")

	// nginx 1: verify. Return 401 if invalid and NGINX will call `auth-signin`
	r.Handle("/verify", p.Verify(true)).Queries("uri", "{uri}")

	// nginx 4: redirect the user back to their originally requested location.
	r.Handle("/", httputil.HandlerFunc(p.nginxPostCallbackRedirect)).
		Queries("uri", "{uri}", urlutil.QuerySessionEncrypted, "", urlutil.QueryRedirectURI, "")

	// traefik 2: save the returned session post authenticate flow
	r.Handle("/", httputil.HandlerFunc(p.forwardedURIHeaderCallback)).
		HeadersRegexp(httputil.HeaderForwardedURI, urlutil.QuerySessionEncrypted)

	// nginx 2 / traefik 1: verify and then start authenticate flow
	r.Handle("/", p.Verify(false))

	return r
}

// nginxPostCallbackRedirect redirects the user to their original destination
// in order to drop the authenticate related query params
func (p *Proxy) nginxPostCallbackRedirect(w http.ResponseWriter, r *http.Request) error {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	httputil.Redirect(w, r, r.FormValue(urlutil.QueryRedirectURI), http.StatusFound)
	return nil
}

// nginxCallback saves the returned session post callback and then returns an
// unauthorized status in order to restart the request flow process. Strangely
// we need to throw a 401 after saving the session to redirect the user
// to their originally desired location.
func (p *Proxy) nginxCallback(w http.ResponseWriter, r *http.Request) error {
	encryptedSession := r.FormValue(urlutil.QuerySessionEncrypted)
	if _, err := p.saveCallbackSession(w, r, encryptedSession); err != nil {
		return httputil.NewError(http.StatusBadRequest, err)
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusUnauthorized)
	return nil
}

// forwardedURIHeaderCallback handles the post-authentication callback from
// forwarding proxies that support the `X-Forwarded-Uri`.
func (p *Proxy) forwardedURIHeaderCallback(w http.ResponseWriter, r *http.Request) error {
	forwardedURL, err := url.Parse(r.Header.Get(httputil.HeaderForwardedURI))
	if err != nil {
		return httputil.NewError(http.StatusBadRequest, err)
	}
	q := forwardedURL.Query()
	redirectURLString := q.Get(urlutil.QueryRedirectURI)
	encryptedSession := q.Get(urlutil.QuerySessionEncrypted)

	if _, err := p.saveCallbackSession(w, r, encryptedSession); err != nil {
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
func (p *Proxy) Verify(verifyOnly bool) http.Handler {
	return httputil.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		var err error
		if status := r.FormValue("auth_status"); status == fmt.Sprint(http.StatusForbidden) {
			return httputil.NewError(http.StatusForbidden, errors.New(http.StatusText(http.StatusForbidden)))
		}

		// the route to validate will be pulled from the uri queryparam
		// or inferred from forwarding headers
		uriString := r.FormValue("uri")
		if uriString == "" {
			if r.Header.Get(httputil.HeaderForwardedProto) == "" || r.Header.Get(httputil.HeaderForwardedHost) == "" {
				return httputil.NewError(http.StatusBadRequest, errors.New("no uri to validate"))

			}
			uriString = r.Header.Get(httputil.HeaderForwardedProto) + "://" + r.Header.Get(httputil.HeaderForwardedHost)
		}

		uri, err := urlutil.ParseAndValidateURL(uriString)
		if err != nil {
			return httputil.NewError(http.StatusBadRequest, err)
		}
		originalRequest := p.getOriginalRequest(r, uri)

		if err := p.authorize(w, originalRequest); err != nil {
			// no session, so redirect
			if _, err := sessions.FromContext(r.Context()); err != nil {
				if verifyOnly {
					return httputil.NewError(http.StatusUnauthorized, err)
				}
				authN := *p.authenticateSigninURL
				q := authN.Query()
				q.Set(urlutil.QueryCallbackURI, uri.String())
				q.Set(urlutil.QueryRedirectURI, uri.String())              // final destination
				q.Set(urlutil.QueryForwardAuth, urlutil.StripPort(r.Host)) // add fwd auth to trusted audience
				authN.RawQuery = q.Encode()
				httputil.Redirect(w, r, urlutil.NewSignedURL(p.SharedKey, &authN).String(), http.StatusFound)
				return nil
			}

			return err
		}

		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, "Access to %s is allowed.", uri.Host)
		return nil
	})
}

func (p *Proxy) getOriginalRequest(r *http.Request, originalURL *url.URL) *http.Request {
	originalRequest := r.Clone(r.Context())
	originalRequest.Host = originalURL.Host
	originalRequest.URL = originalURL
	return originalRequest
}
