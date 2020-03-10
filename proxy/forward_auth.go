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

	r.Handle("/verify", httputil.HandlerFunc(p.nginxCallback)).
		Queries("uri", "{uri}", urlutil.QuerySessionEncrypted, "", urlutil.QueryRedirectURI, "")
	r.Handle("/", httputil.HandlerFunc(p.postSessionSetNOP)).
		Queries("uri", "{uri}",
			urlutil.QuerySessionEncrypted, "",
			urlutil.QueryRedirectURI, "")
	r.Handle("/", httputil.HandlerFunc(p.traefikCallback)).
		HeadersRegexp(httputil.HeaderForwardedURI, urlutil.QuerySessionEncrypted)
	r.Handle("/", p.Verify(false)).Queries("uri", "{uri}")
	r.Handle("/verify", p.Verify(true)).Queries("uri", "{uri}")

	return r
}

// postSessionSetNOP after successfully setting the
func (p *Proxy) postSessionSetNOP(w http.ResponseWriter, r *http.Request) error {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	httputil.Redirect(w, r, r.FormValue(urlutil.QueryRedirectURI), http.StatusFound)
	return nil
}

func (p *Proxy) nginxCallback(w http.ResponseWriter, r *http.Request) error {
	encryptedSession := r.FormValue(urlutil.QuerySessionEncrypted)
	if _, err := p.saveCallbackSession(w, r, encryptedSession); err != nil {
		return httputil.NewError(http.StatusBadRequest, err)
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusUnauthorized)
	return nil
}

func (p *Proxy) traefikCallback(w http.ResponseWriter, r *http.Request) error {
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
		uri, err := urlutil.ParseAndValidateURL(r.FormValue("uri"))
		if err != nil {
			return httputil.NewError(http.StatusBadRequest, err)
		}
		jwt, err := sessions.FromContext(r.Context())
		if err != nil {
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
		var s sessions.State
		if err := p.encoder.Unmarshal([]byte(jwt), &s); err != nil {
			return httputil.NewError(http.StatusBadRequest, err)
		}

		r.Host = uri.Host
		if err := p.authorize(w, r); err != nil {
			return err
		}

		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, "Access to %s is allowed.", uri.Host)
		return nil
	})
}
