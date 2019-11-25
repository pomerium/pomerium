package proxy // import "github.com/pomerium/pomerium/proxy"

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"

	"github.com/pomerium/pomerium/internal/httputil"
	"github.com/pomerium/pomerium/internal/sessions"
	"github.com/pomerium/pomerium/internal/urlutil"
)

func (p *Proxy) registerFwdAuthHandlers() http.Handler {
	r := httputil.NewRouter()
	r.StrictSlash(true)
	r.Use(sessions.RetrieveSession(p.sessionStore))

	r.Handle("/verify", http.HandlerFunc(p.nginxCallback)).
		Queries("uri", "{uri}", urlutil.QuerySessionEncrypted, "", urlutil.QueryRedirectURI, "")
	r.Handle("/", http.HandlerFunc(p.postSessionSetNOP)).
		Queries("uri", "{uri}",
			urlutil.QuerySessionEncrypted, "",
			urlutil.QueryRedirectURI, "")
	r.Handle("/", http.HandlerFunc(p.traefikCallback)).
		HeadersRegexp(httputil.HeaderForwardedURI, urlutil.QuerySessionEncrypted)
	r.Handle("/", p.Verify(false)).Queries("uri", "{uri}")
	r.Handle("/verify", p.Verify(true)).Queries("uri", "{uri}")

	return r
}

// postSessionSetNOP after successfully setting the
func (p *Proxy) postSessionSetNOP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	httputil.Redirect(w, r, r.FormValue(urlutil.QueryRedirectURI), http.StatusFound)
}

func (p *Proxy) nginxCallback(w http.ResponseWriter, r *http.Request) {
	encryptedSession := r.FormValue(urlutil.QuerySessionEncrypted)
	if _, err := p.saveCallbackSession(w, r, encryptedSession); err != nil {
		httputil.ErrorResponse(w, r, httputil.Error(err.Error(), http.StatusBadRequest, err))
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusUnauthorized)
}

func (p *Proxy) traefikCallback(w http.ResponseWriter, r *http.Request) {
	forwardedURL, err := url.Parse(r.Header.Get(httputil.HeaderForwardedURI))
	if err != nil {
		httputil.ErrorResponse(w, r, httputil.Error(err.Error(), http.StatusBadRequest, err))
		return
	}
	q := forwardedURL.Query()
	redirectURLString := q.Get(urlutil.QueryRedirectURI)
	encryptedSession := q.Get(urlutil.QuerySessionEncrypted)

	if _, err := p.saveCallbackSession(w, r, encryptedSession); err != nil {
		httputil.ErrorResponse(w, r, httputil.Error(err.Error(), http.StatusBadRequest, err))
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	httputil.Redirect(w, r, redirectURLString, http.StatusFound)
}

// Verify checks a user's credentials for an arbitrary host. If the user
// is properly authenticated and is authorized to access the supplied host,
// a `200` http status code is returned. If the user is not authenticated, they
// will be redirected to the authenticate service to sign in with their identity
// provider. If the user is unauthorized, a `401` error is returned.
func (p *Proxy) Verify(verifyOnly bool) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		uri, err := urlutil.ParseAndValidateURL(r.FormValue("uri"))
		if err != nil {
			httputil.ErrorResponse(w, r, httputil.Error("bad verification uri", http.StatusBadRequest, err))
			return
		}

		s, err := sessions.FromContext(r.Context())
		if errors.Is(err, sessions.ErrNoSessionFound) || errors.Is(err, sessions.ErrExpired) {
			if verifyOnly {
				httputil.ErrorResponse(w, r, httputil.Error(err.Error(), http.StatusUnauthorized, err))
				return
			}
			authN := *p.authenticateSigninURL
			q := authN.Query()
			q.Set(urlutil.QueryCallbackURI, uri.String())
			q.Set(urlutil.QueryRedirectURI, uri.String())              // final destination
			q.Set(urlutil.QueryForwardAuth, urlutil.StripPort(r.Host)) // add fwd auth to trusted audience
			authN.RawQuery = q.Encode()
			httputil.Redirect(w, r, urlutil.NewSignedURL(p.SharedKey, &authN).String(), http.StatusFound)
			return
		} else if err != nil {
			httputil.ErrorResponse(w, r, httputil.Error(err.Error(), http.StatusUnauthorized, err))
			return
		}
		// depending on the configuration of the fronting proxy, the request Host
		// and/or `X-Forwarded-Host` may be untrustd or change so we reverify
		// the session's validity against the supplied uri
		if err := s.Verify(uri.Hostname()); err != nil {
			httputil.ErrorResponse(w, r, httputil.Error(err.Error(), http.StatusUnauthorized, err))
			return
		}
		p.addPomeriumHeaders(w, r)
		if err := p.authorize(uri.Host, w, r); err != nil {
			return
		}

		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, "Access to %s is allowed.", uri.Host)
	})
}
