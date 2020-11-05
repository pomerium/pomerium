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

	// nginx 1: verify, fronted by ext_authz
	r.Handle("/verify", httputil.HandlerFunc(p.allowUpstream)).
		Queries(urlutil.QueryForwardAuthURI, "{uri}")

	// nginx 4: redirect the user back to their originally requested location.
	r.Handle("/", httputil.HandlerFunc(p.nginxPostCallbackRedirect)).
		Queries(urlutil.QueryForwardAuthURI, "{uri}",
			urlutil.QuerySessionEncrypted, "",
			urlutil.QueryRedirectURI, "")

	// traefik 2: save the returned session post authenticate flow
	r.Handle("/", httputil.HandlerFunc(p.forwardedURIHeaderCallback)).
		HeadersRegexp(httputil.HeaderForwardedURI, urlutil.QuerySessionEncrypted)

	r.Handle("/", httputil.HandlerFunc(p.startAuthN)).
		Queries(urlutil.QueryForwardAuthURI, "{uri}")

	// nginx 2 / traefik 1: verify and then start authenticate flow
	r.Handle("/", httputil.HandlerFunc(p.allowUpstream))

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
	return httputil.NewError(http.StatusUnauthorized, errors.New("mock error to restart redirect flow"))
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

// allowUpstream will return status 200 (OK) unless auth_status is set to forbidden.
// This handler is expected to be behind a routed protected by envoy's control plane (ext_authz).
func (p *Proxy) allowUpstream(w http.ResponseWriter, r *http.Request) error {
	if status := r.FormValue("auth_status"); status == fmt.Sprint(http.StatusForbidden) {
		return httputil.NewError(http.StatusForbidden, errors.New(http.StatusText(http.StatusForbidden)))
	}
	// in forward-auth configuration we want to treat our request headers as response headers
	// so that they can be forwarded by the fronting proxy, if desired
	for k, vs := range r.Header {
		for _, v := range vs {
			w.Header().Set(k, v)
		}
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(http.StatusOK)
	fmt.Fprintln(w, http.StatusText(http.StatusOK))
	return nil
}

// startAuthN redirects an unauthenticated user to start forward-auth
// authentication flow
func (p *Proxy) startAuthN(w http.ResponseWriter, r *http.Request) error {
	state := p.state.Load()
	uriString := r.FormValue(urlutil.QueryForwardAuthURI)
	if uriString == "" {
		uriString = "https://" + // always use HTTPS for external urls
			r.Header.Get(httputil.HeaderForwardedHost) +
			r.Header.Get(httputil.HeaderForwardedURI)
	}
	uri, err := urlutil.ParseAndValidateURL(uriString)
	if err != nil {
		return httputil.NewError(http.StatusBadRequest, err)
	}
	// add any non-empty existing path from the forwarded URI
	if xfu := r.Header.Get(httputil.HeaderForwardedURI); xfu != "" && xfu != "/" {
		uri.Path = xfu
	}

	authN := *state.authenticateSigninURL
	q := authN.Query()
	q.Set(urlutil.QueryCallbackURI, uri.String())
	q.Set(urlutil.QueryRedirectURI, uri.String())              // final destination
	q.Set(urlutil.QueryForwardAuth, urlutil.StripPort(r.Host)) // add fwd auth to trusted audience
	authN.RawQuery = q.Encode()
	httputil.Redirect(w, r, urlutil.NewSignedURL(state.sharedKey, &authN).String(), http.StatusFound)
	return nil
}
