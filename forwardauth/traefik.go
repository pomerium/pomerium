package forwardauth

import (
	"net/http"
	"net/url"

	"github.com/gorilla/mux"

	"github.com/pomerium/pomerium/internal/httputil"
	"github.com/pomerium/pomerium/internal/urlutil"
)

func registerTraefikHandlers(fa *ForwardAuth, r *mux.Router) {
	// traefik 2: save the returned session post authenticate flow
	r.Handle("/", httputil.HandlerFunc(fa.traefikCallback)).
		HeadersRegexp(httputil.HeaderForwardedURI, urlutil.QuerySessionEncrypted)

	// traefik 1: verify and then start authenticate flow
	r.Handle("/", fa.Verify(false))
}

// traefikCallback handles the post-authentication callback from
// forwarding proxies that support the `X-Forwarded-Uri`.
func (fa *ForwardAuth) traefikCallback(w http.ResponseWriter, r *http.Request) error {
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
