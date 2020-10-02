package proxy

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"

	"github.com/pomerium/pomerium/internal/httputil"
	"github.com/pomerium/pomerium/internal/urlutil"
)

// registerFwdAuthHandlers returns a set of handlers that support using pomerium
// as a "forward-auth" provider with other reverse proxies like nginx, traefik.
//
// see : https://www.pomerium.io/configuration/#forward-auth
func (p *Proxy) registerFwdAuthHandlers() http.Handler {
	r := httputil.NewRouter()

	// NGNIX's forward-auth capabilities are split across two settings:
	// `auth-url` and `auth-signin` which correspond to `verify` and `auth-url`
	//
	// NOTE: Route order matters here which makes the request flow confusing
	// 		 to reason about so each step has a postfix order step.

	// nginx 3: save the returned session post authenticate flow
	r.Handle("/verify", httputil.HandlerFunc(p.nginxCallback)).
		Queries(urlutil.QueryForwardAuthURI, "{uri}",
			urlutil.QuerySessionEncrypted, "",
			urlutil.QueryRedirectURI, "")

	// nginx 1: verify. Return 401 if invalid and NGINX will call `auth-signin`
	r.Handle("/verify", httputil.HandlerFunc(p.ok)).
		Queries(urlutil.QueryForwardAuthURI, "{uri}")

	// nginx 4: redirect the user back to their originally requested location.
	r.Handle("/", httputil.HandlerFunc(p.nginxPostCallbackRedirect)).
		Queries(urlutil.QueryForwardAuthURI, "{uri}",
			urlutil.QuerySessionEncrypted, "",
			urlutil.QueryRedirectURI, "")

	// traefik 2: save the returned session post authenticate flow
	r.Handle("/", httputil.HandlerFunc(p.forwardedURIHeaderCallback)).
		HeadersRegexp(httputil.HeaderForwardedURI, urlutil.QuerySessionEncrypted)

	r.Handle("/", httputil.HandlerFunc(p.forwardAuthRedirectToSignInWithURI)).
		Queries(urlutil.QueryForwardAuthURI, "{uri}")

	// nginx 2 / traefik 1: verify and then start authenticate flow
	r.Handle("/", httputil.HandlerFunc(p.ok))

	return r
}

// nginxPostCallbackRedirect redirects the user to their original destination
// in order to drop the authenticate related query params
func (p *Proxy) nginxPostCallbackRedirect(w http.ResponseWriter, r *http.Request) error {
	u, err := url.Parse(r.FormValue(urlutil.QueryRedirectURI))
	if err != nil {
		return httputil.NewError(http.StatusBadRequest, err)
	}
	u = urlutil.ParseEnvoyQueryParams(u)
	q := u.Query()
	q.Del(urlutil.QueryForwardAuthURI)
	u.RawQuery = q.Encode()
	httputil.Redirect(w, r, u.String(), http.StatusFound)
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
	return httputil.NewError(http.StatusUnauthorized, errors.New("nginxCallback"))
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
	httputil.Redirect(w, r, redirectURLString, http.StatusFound)
	return nil
}

// ok will always return http status 200 (OK) and is assumed to always be
// behind a protected (ext_authz) envoy control plane managed endpoint.
func (p *Proxy) ok(w http.ResponseWriter, r *http.Request) error {

	if status := r.FormValue("auth_status"); status == fmt.Sprint(http.StatusForbidden) {
		return httputil.NewError(http.StatusForbidden, errors.New(http.StatusText(http.StatusForbidden)))
	}

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(http.StatusOK)
	fmt.Fprintln(w, http.StatusText(http.StatusOK))
	return nil

}

// forwardAuthRedirectToSignInWithURI redirects request to authenticate signin url,
// with all necessary information extracted from given input uri.
func (p *Proxy) forwardAuthRedirectToSignInWithURI(w http.ResponseWriter, r *http.Request) error {
	state := p.state.Load()
	uri, err := getURIStringFromRequest(r)
	if err != nil {
		return httputil.NewError(http.StatusBadRequest, err)
	}
	// Traefik set the uri in the header, we must set it in redirect uri if present. Otherwise, request like
	// https://example.com/foo will be redirected to https://example.com after authentication.
	if xfu := r.Header.Get(httputil.HeaderForwardedURI); xfu != "" && xfu != "/" {
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
	return nil
}

func getURIStringFromRequest(r *http.Request) (*url.URL, error) {
	// the route to validate will be pulled from the uri queryparam
	// or inferred from forwarding headers
	uriString := r.FormValue(urlutil.QueryForwardAuthURI)
	if uriString == "" {
		if r.Header.Get(httputil.HeaderForwardedHost) == "" {
			return nil, errors.New("no uri to validate")
		}
		// Always assume HTTPS for application callback
		uriString = "https://" +
			r.Header.Get(httputil.HeaderForwardedHost) +
			r.Header.Get(httputil.HeaderForwardedURI)
	}
	return urlutil.ParseAndValidateURL(uriString)
}
