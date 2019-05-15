package authenticate // import "github.com/pomerium/pomerium/authenticate"

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/pomerium/pomerium/internal/cryptutil"
	"github.com/pomerium/pomerium/internal/httputil"
	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/internal/middleware"
	"github.com/pomerium/pomerium/internal/sessions"
	"github.com/pomerium/pomerium/internal/version"
)

// CSPHeaders adds content security headers for authenticate's handlers
var CSPHeaders = map[string]string{
	"Content-Security-Policy": "default-src 'none'; style-src 'self' 'sha256-pSTVzZsFAqd2U3QYu+BoBDtuJWaPM/+qMy/dBRrhb5Y='; img-src 'self';",
	"Referrer-Policy":         "Same-origin",
}

// Handler returns the authenticate service's HTTP request multiplexer, and routes.
func (a *Authenticate) Handler() http.Handler {
	// validation middleware chain
	c := middleware.NewChain()
	c = c.Append(middleware.SetHeaders(CSPHeaders))
	validate := c.Append(middleware.ValidateSignature(a.SharedKey))
	validate = validate.Append(middleware.ValidateRedirectURI(a.RedirectURL))
	mux := http.NewServeMux()
	mux.Handle("/robots.txt", c.ThenFunc(a.RobotsTxt))
	// Identity Provider (IdP) callback endpoints and callbacks
	mux.Handle("/start", c.ThenFunc(a.OAuthStart))
	mux.Handle("/oauth2/callback", c.ThenFunc(a.OAuthCallback))
	// authenticate-server endpoints
	mux.Handle("/sign_in", validate.ThenFunc(a.SignIn))
	mux.Handle("/sign_out", validate.ThenFunc(a.SignOut)) // GET POST
	return mux
}

// RobotsTxt handles the /robots.txt route.
func (a *Authenticate) RobotsTxt(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, "User-agent: *\nDisallow: /")
}

func (a *Authenticate) authenticate(w http.ResponseWriter, r *http.Request) (*sessions.SessionState, error) {
	session, err := a.sessionStore.LoadSession(r)
	if err != nil {
		log.FromRequest(r).Error().Err(err).Msg("authenticate: failed to load session")
		a.sessionStore.ClearSession(w, r)
		return nil, err
	}

	if session.RefreshPeriodExpired() {
		newSession, err := a.provider.Refresh(r.Context(), session)
		if err != nil {
			log.FromRequest(r).Error().Err(err).Msg("authenticate: failed to refresh session")
			a.sessionStore.ClearSession(w, r)
			return nil, err
		}
		err = a.sessionStore.SaveSession(w, r, newSession)
		if err != nil {
			log.FromRequest(r).Error().Err(err).Msg("authenticate: could not save refreshed session")
			a.sessionStore.ClearSession(w, r)
			return nil, err
		}
	} else {
		// The session has not exceeded it's lifetime or requires refresh
		ok, err := a.provider.Validate(r.Context(), session.IDToken)
		if !ok || err != nil {
			log.FromRequest(r).Error().Err(err).Msg("authenticate: invalid session state")
			a.sessionStore.ClearSession(w, r)
			return nil, httputil.ErrUserNotAuthorized
		}
		err = a.sessionStore.SaveSession(w, r, session)
		if err != nil {
			log.FromRequest(r).Error().Err(err).Msg("authenticate: failed to save valid session")
			a.sessionStore.ClearSession(w, r)
			return nil, err
		}
	}

	return session, nil
}

// SignIn handles the sign_in endpoint. It attempts to authenticate the user,
// and if the user is not authenticated, it renders a sign in page.
func (a *Authenticate) SignIn(w http.ResponseWriter, r *http.Request) {
	session, err := a.authenticate(w, r)
	if err != nil {
		log.FromRequest(r).Warn().Err(err).Msg("authenticate: authenticate error")
		a.sessionStore.ClearSession(w, r)
		a.OAuthStart(w, r)
	}
	log.FromRequest(r).Debug().Msg("authenticate: user authenticated")
	a.ProxyCallback(w, r, session)
}

// ProxyCallback redirects the user back to proxy service along with an encrypted payload, as
// url params, of the user's session state as specified in RFC6749 3.1.2.
// https://tools.ietf.org/html/rfc6749#section-3.1.2
func (a *Authenticate) ProxyCallback(w http.ResponseWriter, r *http.Request, session *sessions.SessionState) {
	err := r.ParseForm()
	if err != nil {
		httputil.ErrorResponse(w, r, err.Error(), http.StatusInternalServerError)
		return
	}
	// original `state` parameter received from the proxy application.
	state := r.Form.Get("state")
	if state == "" {
		httputil.ErrorResponse(w, r, "no state parameter supplied", http.StatusForbidden)
		return
	}
	// redirect url of proxy-service
	redirectURI := r.Form.Get("redirect_uri")
	if redirectURI == "" {
		httputil.ErrorResponse(w, r, "no redirect_uri parameter supplied", http.StatusForbidden)
		return
	}

	redirectURL, err := url.Parse(redirectURI)
	if err != nil {
		httputil.ErrorResponse(w, r, "malformed redirect_uri parameter passed", http.StatusBadRequest)
		return
	}
	// encrypt session state as json blob
	encrypted, err := sessions.MarshalSession(session, a.cipher)
	if err != nil {
		httputil.ErrorResponse(w, r, err.Error(), http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, getAuthCodeRedirectURL(redirectURL, state, string(encrypted)), http.StatusFound)
}

func getAuthCodeRedirectURL(redirectURL *url.URL, state, authCode string) string {
	u, _ := url.Parse(redirectURL.String())
	params, _ := url.ParseQuery(u.RawQuery)
	params.Set("code", authCode)
	params.Set("state", state)
	u.RawQuery = params.Encode()
	if u.Scheme == "" {
		u.Scheme = "https"
	}
	return u.String()
}

// SignOut signs the user out by trying to revoke the user's remote identity session along with
// the associated local session state. Handles both GET and POST.
func (a *Authenticate) SignOut(w http.ResponseWriter, r *http.Request) {
	err := r.ParseForm()
	if err != nil {
		httputil.ErrorResponse(w, r, err.Error(), http.StatusInternalServerError)
		return
	}
	// pretty safe to say that no matter what heppanes here, we want to revoke the local session
	redirectURI := r.Form.Get("redirect_uri")
	session, err := a.sessionStore.LoadSession(r)
	if err != nil {
		log.Error().Err(err).Msg("authenticate: signout failed to load session")
		httputil.ErrorResponse(w, r, "No session found to log out", http.StatusBadRequest)
		return
	}
	if r.Method == http.MethodGet {
		signature := r.Form.Get("sig")
		timestamp := r.Form.Get("ts")
		destinationURL, err := url.Parse(redirectURI)
		if err != nil {
			log.Error().Err(err).Msg("authenticate: malformed destination url")
			httputil.ErrorResponse(w, r, "Malformed destination URL", http.StatusBadRequest)
			return
		}
		t := struct {
			Redirect    string
			Signature   string
			Timestamp   string
			Destination string
			Email       string
			Version     string
		}{
			Redirect:    redirectURI,
			Signature:   signature,
			Timestamp:   timestamp,
			Destination: destinationURL.Host,
			Email:       session.Email,
			Version:     version.FullVersion(),
		}
		a.templates.ExecuteTemplate(w, "sign_out.html", t)
		w.WriteHeader(http.StatusOK)
		return
	}
	a.sessionStore.ClearSession(w, r)
	err = a.provider.Revoke(session.AccessToken)
	if err != nil {
		log.Error().Err(err).Msg("authenticate: failed to revoke user session")
		httputil.ErrorResponse(w, r, fmt.Sprintf("could not revoke session: %s ", err.Error()), http.StatusBadRequest)
		return
	}
	http.Redirect(w, r, redirectURI, http.StatusFound)
}

// OAuthStart starts the authenticate process by redirecting to the identity provider.
// https://tools.ietf.org/html/rfc6749#section-4.2.1
func (a *Authenticate) OAuthStart(w http.ResponseWriter, r *http.Request) {
	authRedirectURL := a.RedirectURL.ResolveReference(r.URL)

	nonce := fmt.Sprintf("%x", cryptutil.GenerateKey())
	a.csrfStore.SetCSRF(w, r, nonce)

	// verify redirect uri is from the root domain
	if !middleware.SameSubdomain(authRedirectURL, a.RedirectURL) {
		httputil.ErrorResponse(w, r, "Invalid redirect parameter", http.StatusBadRequest)
		return
	}
	// verify proxy url is from the root domain
	proxyRedirectURL, err := url.Parse(authRedirectURL.Query().Get("redirect_uri"))
	if err != nil || !middleware.SameSubdomain(proxyRedirectURL, a.RedirectURL) {
		httputil.ErrorResponse(w, r, "Invalid redirect parameter", http.StatusBadRequest)
		return
	}

	// get the signature and timestamp values then compare hmac
	proxyRedirectSig := authRedirectURL.Query().Get("sig")
	ts := authRedirectURL.Query().Get("ts")
	if !middleware.ValidSignature(proxyRedirectURL.String(), proxyRedirectSig, ts, a.SharedKey) {
		httputil.ErrorResponse(w, r, "Invalid redirect parameter", http.StatusBadRequest)
		return
	}

	// concat base64'd nonce and authenticate url to make state
	state := base64.URLEncoding.EncodeToString([]byte(fmt.Sprintf("%v:%v", nonce, authRedirectURL.String())))
	// build the provider sign in url
	signInURL := a.provider.GetSignInURL(state)

	http.Redirect(w, r, signInURL, http.StatusFound)
}

// OAuthCallback handles the callback from the identity provider. Displays an error page if there
// was an error. If successful, the user is redirected back to the proxy-service.
func (a *Authenticate) OAuthCallback(w http.ResponseWriter, r *http.Request) {
	redirect, err := a.getOAuthCallback(w, r)
	switch h := err.(type) {
	case nil:
		break
	case httputil.HTTPError:
		log.Error().Err(err).Msg("authenticate: oauth callback error")
		httputil.ErrorResponse(w, r, h.Message, h.Code)
		return
	default:
		log.Error().Err(err).Msg("authenticate: unexpected oauth callback error")
		httputil.ErrorResponse(w, r, "Internal Error", http.StatusInternalServerError)
		return
	}
	// redirect back to the proxy-service
	http.Redirect(w, r, redirect, http.StatusFound)
}

// getOAuthCallback completes the oauth cycle from an identity provider's callback
func (a *Authenticate) getOAuthCallback(w http.ResponseWriter, r *http.Request) (string, error) {
	err := r.ParseForm()
	if err != nil {
		return "", httputil.HTTPError{Code: http.StatusInternalServerError, Message: err.Error()}
	}
	errorString := r.Form.Get("error")
	if errorString != "" {
		log.FromRequest(r).Error().Str("Error", errorString).Msg("authenticate: provider returned error")
		return "", httputil.HTTPError{Code: http.StatusForbidden, Message: errorString}
	}
	code := r.Form.Get("code")
	if code == "" {
		log.FromRequest(r).Error().Err(err).Msg("authenticate: provider missing code")
		return "", httputil.HTTPError{Code: http.StatusBadRequest, Message: "Missing Code"}
	}

	session, err := a.provider.Authenticate(code)
	if err != nil {
		log.FromRequest(r).Error().Err(err).Msg("authenticate: error redeeming authenticate code")
		return "", httputil.HTTPError{Code: http.StatusInternalServerError, Message: err.Error()}
	}

	bytes, err := base64.URLEncoding.DecodeString(r.Form.Get("state"))
	if err != nil {
		log.FromRequest(r).Error().Err(err).Msg("authenticate: failed decoding state")
		return "", httputil.HTTPError{Code: http.StatusBadRequest, Message: "Couldn't decode state"}
	}
	s := strings.SplitN(string(bytes), ":", 2)
	if len(s) != 2 {
		return "", httputil.HTTPError{Code: http.StatusBadRequest, Message: "Invalid State"}
	}
	nonce := s[0]
	redirect := s[1]
	c, err := a.csrfStore.GetCSRF(r)
	if err != nil {
		log.FromRequest(r).Error().Err(err).Msg("authenticate: bad csrf")
		return "", httputil.HTTPError{Code: http.StatusForbidden, Message: "Missing CSRF token"}
	}
	a.csrfStore.ClearCSRF(w, r)
	if c.Value != nonce {
		log.FromRequest(r).Error().Err(err).Msg("authenticate: csrf mismatch")
		return "", httputil.HTTPError{Code: http.StatusForbidden, Message: "CSRF failed"}
	}

	redirectURL, err := url.Parse(redirect)
	if err != nil {
		log.FromRequest(r).Error().Err(err).Msg("authenticate: couldn't parse redirect url")
		return "", httputil.HTTPError{Code: http.StatusForbidden, Message: "Couldn't parse redirect url"}
	}

	if !middleware.SameSubdomain(redirectURL, a.RedirectURL) {
		return "", httputil.HTTPError{Code: http.StatusForbidden, Message: "Invalid Redirect URI domain"}
	}

	err = a.sessionStore.SaveSession(w, r, session)
	if err != nil {
		log.Error().Err(err).Msg("internal error")
		return "", httputil.HTTPError{Code: http.StatusInternalServerError, Message: "Internal Error"}
	}
	return redirect, nil
}
