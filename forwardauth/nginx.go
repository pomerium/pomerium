package forwardauth

import (
	"net/http"

	"github.com/gorilla/mux"

	"github.com/pomerium/pomerium/internal/httputil"
	"github.com/pomerium/pomerium/internal/urlutil"
)

type nginx struct {
	fa *ForwardAuth
}

func (n *nginx) Init(fa *ForwardAuth, r *mux.Router) {
	n.fa = fa
	// NGNIX's forward-auth capabilities are split across two settings:
	// `auth-url` and `auth-signin` which correspond to `verify` and `auth-url`
	//
	// NOTE: Route order matters here which makes the request flow confusing
	//       to reason about so each step has a postfix order step.

	// nginx 3: save the returned session post authenticate flow
	r.Handle("/verify", httputil.HandlerFunc(n.nginxCallback)).
		Queries("uri", "{uri}", urlutil.QuerySessionEncrypted, "", urlutil.QueryRedirectURI, "")

	// nginx 1: verify. Return 401 if invalid and NGINX will call `auth-signin`
	r.Handle("/verify", n.fa.Verify(true)).Queries("uri", "{uri}")

	// nginx 4: redirect the user back to their originally requested location.
	r.Handle("/", httputil.HandlerFunc(n.nginxPostCallbackRedirect)).
		Queries("uri", "{uri}", urlutil.QuerySessionEncrypted, "", urlutil.QueryRedirectURI, "")

	// nginx 2: verify and then start authenticate flow
	r.Handle("/", n.fa.Verify(false))
}

// nginxPostCallbackRedirect redirects the user to their original destination
// in order to drop the authenticate related query params
func (n *nginx) nginxPostCallbackRedirect(w http.ResponseWriter, r *http.Request) error {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	httputil.Redirect(w, r, r.FormValue(urlutil.QueryRedirectURI), http.StatusFound)
	return nil
}

// nginxCallback saves the returned session post callback and then returns an
// unauthorized status in order to restart the request flow process. Strangely
// we need to throw a 401 after saving the session to redirect the user
// to their originally desired location.
func (n *nginx) nginxCallback(w http.ResponseWriter, r *http.Request) error {
	encryptedSession := r.FormValue(urlutil.QuerySessionEncrypted)
	if err := n.fa.saveCallbackSession(w, r, encryptedSession); err != nil {
		return httputil.NewError(http.StatusBadRequest, err)
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusUnauthorized)
	return nil
}
