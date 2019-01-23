package authenticate // import "github.com/pomerium/pomerium/authenticate"

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/pomerium/pomerium/internal/cryptutil"
	"github.com/pomerium/pomerium/internal/httputil"
	"github.com/pomerium/pomerium/internal/log"
	m "github.com/pomerium/pomerium/internal/middleware"
	"github.com/pomerium/pomerium/internal/sessions"
	"github.com/pomerium/pomerium/internal/version"
)

var securityHeaders = map[string]string{
	"Strict-Transport-Security": "max-age=31536000",
	"X-Frame-Options":           "DENY",
	"X-Content-Type-Options":    "nosniff",
	"X-XSS-Protection":          "1; mode=block",
	"Content-Security-Policy":   "default-src 'none'; style-src 'self' 'sha256-pSTVzZsFAqd2U3QYu+BoBDtuJWaPM/+qMy/dBRrhb5Y='; img-src 'self';",
	"Referrer-Policy":           "Same-origin",
}

// Handler returns the Http.Handlers for authentication, callback, and refresh
func (p *Authenticate) Handler() http.Handler {
	mux := http.NewServeMux()
	// we setup global endpoints that should respond to any hostname
	mux.HandleFunc("/ping", m.WithMethods(p.PingPage, "GET"))

	serviceMux := http.NewServeMux()
	// standard rest and healthcheck endpoints
	serviceMux.HandleFunc("/ping", m.WithMethods(p.PingPage, "GET"))
	serviceMux.HandleFunc("/robots.txt", m.WithMethods(p.RobotsTxt, "GET"))
	// Identity Provider (IdP) endpoints and callbacks
	serviceMux.HandleFunc("/start", m.WithMethods(p.OAuthStart, "GET"))
	serviceMux.HandleFunc("/oauth2/callback", m.WithMethods(p.OAuthCallback, "GET"))
	// authenticator-server endpoints, todo(bdd): make gRPC
	serviceMux.HandleFunc("/sign_in", m.WithMethods(p.validateSignature(p.SignIn), "GET"))
	serviceMux.HandleFunc("/sign_out", m.WithMethods(p.validateSignature(p.SignOut), "GET", "POST"))
	serviceMux.HandleFunc("/profile", m.WithMethods(p.validateExisting(p.GetProfile), "GET"))
	serviceMux.HandleFunc("/validate", m.WithMethods(p.validateExisting(p.ValidateToken), "GET"))
	serviceMux.HandleFunc("/redeem", m.WithMethods(p.validateExisting(p.Redeem), "POST"))
	serviceMux.HandleFunc("/refresh", m.WithMethods(p.validateExisting(p.Refresh), "POST"))

	// NOTE: we have to include trailing slash for the router to match the host header
	host := p.RedirectURL.Host
	if !strings.HasSuffix(host, "/") {
		host = fmt.Sprintf("%s/", host)
	}
	mux.Handle(host, serviceMux) // setup our service mux to only handle our required host header

	return m.SetHeadersOld(mux, securityHeaders)
}

// validateSignature wraps a common collection of middlewares to validate signatures
func (p *Authenticate) validateSignature(f http.HandlerFunc) http.HandlerFunc {
	return validateRedirectURI(validateSignature(f, p.SharedKey), p.ProxyRootDomains)

}

// validateSignature wraps a common collection of middlewares to validate
// a (presumably) existing user session
func (p *Authenticate) validateExisting(f http.HandlerFunc) http.HandlerFunc {
	return m.ValidateClientSecret(f, p.SharedKey)
}

// RobotsTxt handles the /robots.txt route.
func (p *Authenticate) RobotsTxt(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, "User-agent: *\nDisallow: /")
}

// PingPage handles the /ping route
func (p *Authenticate) PingPage(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, "OK")
}

// SignInPage directs the user to the sign in page. Takes a `redirect_uri` param.
func (p *Authenticate) SignInPage(w http.ResponseWriter, r *http.Request) {
	// requestLog := log.WithRequest(req, "authenticate.SignInPage")
	redirectURL := p.RedirectURL.ResolveReference(r.URL)
	// validateRedirectURI middleware already ensures that this is a valid URL
	destinationURL, _ := url.Parse(redirectURL.Query().Get("redirect_uri"))
	t := struct {
		ProviderName   string
		AllowedDomains []string
		Redirect       string
		Destination    string
		Version        string
	}{
		ProviderName:   p.provider.Data().ProviderName,
		AllowedDomains: p.AllowedDomains,
		Redirect:       redirectURL.String(),
		Destination:    destinationURL.Host,
		Version:        version.FullVersion(),
	}
	log.Ctx(r.Context()).Info().
		Str("ProviderName", p.provider.Data().ProviderName).
		Str("Redirect", redirectURL.String()).
		Str("Destination", destinationURL.Host).
		Str("AllowedDomains", strings.Join(p.AllowedDomains, ", ")).
		Msg("authenticate.SignInPage")
	w.WriteHeader(http.StatusOK)
	p.templates.ExecuteTemplate(w, "sign_in.html", t)
}

func (p *Authenticate) authenticate(w http.ResponseWriter, r *http.Request) (*sessions.SessionState, error) {
	// requestLog := log.WithRequest(req, "authenticate.authenticate")
	session, err := p.sessionStore.LoadSession(r)
	if err != nil {
		log.Error().Err(err).Msg("authenticate.authenticate")
		p.sessionStore.ClearSession(w, r)
		return nil, err
	}

	// ensure sessions lifetime has not expired
	if session.LifetimePeriodExpired() {
		log.Ctx(r.Context()).Warn().Msg("lifetime expired")
		p.sessionStore.ClearSession(w, r)
		return nil, sessions.ErrLifetimeExpired
	}
	// check if session refresh period is up
	if session.RefreshPeriodExpired() {
		ok, err := p.provider.RefreshSessionIfNeeded(session)
		if err != nil {
			log.Ctx(r.Context()).Error().Err(err).Msg("failed to refresh session")
			p.sessionStore.ClearSession(w, r)
			return nil, err
		}
		if !ok {
			log.Ctx(r.Context()).Error().Msg("user unauthorized after refresh")
			p.sessionStore.ClearSession(w, r)
			return nil, httputil.ErrUserNotAuthorized
		}
		// update refresh'd session in cookie
		err = p.sessionStore.SaveSession(w, r, session)
		if err != nil {
			// We refreshed the session successfully, but failed to save it.
			// This could be from failing to encode the session properly.
			// But, we clear the session cookie and reject the request
			log.Ctx(r.Context()).Error().Err(err).Msg("could not save refreshed session")
			p.sessionStore.ClearSession(w, r)
			return nil, err
		}
	} else {
		// The session has not exceeded it's lifetime or requires refresh
		ok := p.provider.ValidateSessionState(session)
		if !ok {
			log.Ctx(r.Context()).Error().Msg("invalid session state")
			p.sessionStore.ClearSession(w, r)
			return nil, httputil.ErrUserNotAuthorized
		}
		err = p.sessionStore.SaveSession(w, r, session)
		if err != nil {
			log.Ctx(r.Context()).Error().Err(err).Msg("failed to save valid session")
			p.sessionStore.ClearSession(w, r)
			return nil, err
		}
	}

	if !p.Validator(session.Email) {
		log.Ctx(r.Context()).Error().Msg("invalid email user")
		return nil, httputil.ErrUserNotAuthorized
	}
	return session, nil
}

// SignIn handles the /sign_in endpoint. It attempts to authenticate the user,
// and if the user is not authenticated, it renders a sign in page.
func (p *Authenticate) SignIn(w http.ResponseWriter, r *http.Request) {
	// We attempt to authenticate the user. If they cannot be authenticated, we render a sign-in
	// page.
	//
	// If the user is authenticated, we redirect back to the proxy application
	// at the `redirect_uri`, with a temporary token.
	//
	// TODO: It is possible for a user to visit this page without a redirect destination.
	// Should we allow the user to authenticate? If not, what should be the proposed workflow?

	session, err := p.authenticate(w, r)
	switch err {
	case nil:
		// User is authenticated, redirect back to the proxy application
		// with the necessary state
		p.ProxyOAuthRedirect(w, r, session)
	case http.ErrNoCookie:
		log.Error().Err(err).Msg("authenticate.SignIn : err no cookie")
		if p.skipProviderButton {
			p.skipButtonOAuthStart(w, r)
		} else {
			p.SignInPage(w, r)
		}
	case sessions.ErrLifetimeExpired, sessions.ErrInvalidSession:
		log.Error().Err(err).Msg("authenticate.SignIn : invalid cookie cookie")
		p.sessionStore.ClearSession(w, r)
		if p.skipProviderButton {
			p.skipButtonOAuthStart(w, r)
		} else {
			p.SignInPage(w, r)
		}
	default:
		log.Error().Err(err).Msg("authenticate.SignIn : unknown error cookie")
		httputil.ErrorResponse(w, r, err.Error(), httputil.CodeForError(err))
	}
}

// ProxyOAuthRedirect redirects the user back to sso proxy's redirection endpoint.
func (p *Authenticate) ProxyOAuthRedirect(w http.ResponseWriter, r *http.Request, session *sessions.SessionState) {
	// This workflow corresponds to Section 3.1.2 of the OAuth2 RFC.
	// See https://tools.ietf.org/html/rfc6749#section-3.1.2 for more specific information.
	//
	// We redirect the user back to the proxy application's redirection endpoint; in the
	// sso proxy, this is the `/oauth/callback` endpoint.
	//
	// We must provide the proxy with a temporary authorization code via the `code` parameter,
	// which they can use to redeem an access token for subsequent API calls.
	//
	// We must also include the original `state` parameter received from the proxy application.

	err := r.ParseForm()
	if err != nil {
		httputil.ErrorResponse(w, r, err.Error(), http.StatusInternalServerError)
		return
	}

	state := r.Form.Get("state")
	if state == "" {
		httputil.ErrorResponse(w, r, "no state parameter supplied", http.StatusForbidden)
		return
	}

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

	encrypted, err := sessions.MarshalSession(session, p.cipher)
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

// SignOut signs the user out.
func (p *Authenticate) SignOut(w http.ResponseWriter, r *http.Request) {
	redirectURI := r.Form.Get("redirect_uri")
	if r.Method == "GET" {
		p.SignOutPage(w, r, "")
		return
	}

	session, err := p.sessionStore.LoadSession(r)
	switch err {
	case nil:
		break
	case http.ErrNoCookie: // if there's no cookie in the session we can just redirect
		http.Redirect(w, r, redirectURI, http.StatusFound)
		return
	default:
		// a different error, clear the session cookie and redirect
		log.Error().Err(err).Msg("authenticate.SignOut : error loading cookie session")
		p.sessionStore.ClearSession(w, r)
		http.Redirect(w, r, redirectURI, http.StatusFound)
		return
	}

	err = p.provider.Revoke(session)
	if err != nil {
		log.Error().Err(err).Msg("authenticate.SignOut : error revoking session")
		p.SignOutPage(w, r, "An error occurred during sign out. Please try again.")
		return
	}
	p.sessionStore.ClearSession(w, r)
	http.Redirect(w, r, redirectURI, http.StatusFound)
}

// SignOutPage renders a sign out page with a message
func (p *Authenticate) SignOutPage(w http.ResponseWriter, r *http.Request, message string) {
	log.FromRequest(r).Debug().Msg("This is just a test to make sure signout works")
	// validateRedirectURI middleware already ensures that this is a valid URL
	redirectURI := r.Form.Get("redirect_uri")
	session, err := p.sessionStore.LoadSession(r)
	if err != nil {
		http.Redirect(w, r, redirectURI, http.StatusFound)
		return
	}

	signature := r.Form.Get("sig")
	timestamp := r.Form.Get("ts")
	destinationURL, _ := url.Parse(redirectURI)

	// An error message indicates that an internal server error occurred
	if message != "" {
		w.WriteHeader(http.StatusInternalServerError)
	}

	t := struct {
		Redirect    string
		Signature   string
		Timestamp   string
		Message     string
		Destination string
		Email       string
		Version     string
	}{
		Redirect:    redirectURI,
		Signature:   signature,
		Timestamp:   timestamp,
		Message:     message,
		Destination: destinationURL.Host,
		Email:       session.Email,
		Version:     version.FullVersion(),
	}
	p.templates.ExecuteTemplate(w, "sign_out.html", t)
	return
}

// OAuthStart starts the authentication process by redirecting to the provider. It provides a
// `redirectURI`, allowing the provider to redirect back to the sso proxy after authentication.
func (p *Authenticate) OAuthStart(w http.ResponseWriter, r *http.Request) {
	authRedirectURL, err := url.Parse(r.URL.Query().Get("redirect_uri"))
	if err != nil {
		httputil.ErrorResponse(w, r, "Invalid redirect parameter", http.StatusBadRequest)
		return
	}
	p.helperOAuthStart(w, r, authRedirectURL)
}

func (p *Authenticate) skipButtonOAuthStart(w http.ResponseWriter, r *http.Request) {
	p.helperOAuthStart(w, r, p.RedirectURL.ResolveReference(r.URL))
}

func (p *Authenticate) helperOAuthStart(w http.ResponseWriter, r *http.Request, authRedirectURL *url.URL) {

	nonce := fmt.Sprintf("%x", cryptutil.GenerateKey())
	p.csrfStore.SetCSRF(w, r, nonce)

	if !validRedirectURI(authRedirectURL.String(), p.ProxyRootDomains) {
		httputil.ErrorResponse(w, r, "Invalid redirect parameter", http.StatusBadRequest)
		return
	}

	proxyRedirectURL, err := url.Parse(authRedirectURL.Query().Get("redirect_uri"))
	if err != nil || !validRedirectURI(proxyRedirectURL.String(), p.ProxyRootDomains) {
		httputil.ErrorResponse(w, r, "Invalid redirect parameter", http.StatusBadRequest)
		return
	}

	proxyRedirectSig := authRedirectURL.Query().Get("sig")
	ts := authRedirectURL.Query().Get("ts")
	if !validSignature(proxyRedirectURL.String(), proxyRedirectSig, ts, p.SharedKey) {
		httputil.ErrorResponse(w, r, "Invalid redirect parameter", http.StatusBadRequest)
		return
	}

	state := base64.URLEncoding.EncodeToString([]byte(fmt.Sprintf("%v:%v", nonce, authRedirectURL.String())))

	signInURL := p.provider.GetSignInURL(state)

	http.Redirect(w, r, signInURL, http.StatusFound)
}

func (p *Authenticate) redeemCode(host, code string) (*sessions.SessionState, error) {
	session, err := p.provider.Redeem(code)
	if err != nil {
		return nil, err
	}
	if session.Email == "" {
		return nil, fmt.Errorf("no email included in session")
	}

	return session, nil

}

// getOAuthCallback completes the oauth cycle from an identity provider's callback
func (p *Authenticate) getOAuthCallback(w http.ResponseWriter, r *http.Request) (string, error) {
	// requestLog := log.WithRequest(req, "authenticate.getOAuthCallback")
	// finish the oauth cycle
	err := r.ParseForm()
	if err != nil {
		return "", httputil.HTTPError{Code: http.StatusInternalServerError, Message: err.Error()}
	}
	errorString := r.Form.Get("error")
	if errorString != "" {
		return "", httputil.HTTPError{Code: http.StatusForbidden, Message: errorString}
	}
	code := r.Form.Get("code")
	if code == "" {
		return "", httputil.HTTPError{Code: http.StatusBadRequest, Message: "Missing Code"}
	}

	session, err := p.redeemCode(r.Host, code)
	if err != nil {
		log.Ctx(r.Context()).Error().Err(err).Msg("error redeeming authentication code")
		return "", err
	}

	bytes, err := base64.URLEncoding.DecodeString(r.Form.Get("state"))
	if err != nil {
		return "", httputil.HTTPError{Code: http.StatusInternalServerError, Message: "Invalid State"}
	}
	s := strings.SplitN(string(bytes), ":", 2)
	if len(s) != 2 {
		return "", httputil.HTTPError{Code: http.StatusInternalServerError, Message: "Invalid State"}
	}
	nonce := s[0]
	redirect := s[1]
	c, err := p.csrfStore.GetCSRF(r)
	if err != nil {
		return "", httputil.HTTPError{Code: http.StatusForbidden, Message: "Missing CSRF token"}
	}
	p.csrfStore.ClearCSRF(w, r)
	if c.Value != nonce {
		log.Ctx(r.Context()).Error().Err(err).Msg("csrf token mismatch")
		return "", httputil.HTTPError{Code: http.StatusForbidden, Message: "csrf failed"}
	}

	if !validRedirectURI(redirect, p.ProxyRootDomains) {
		return "", httputil.HTTPError{Code: http.StatusForbidden, Message: "Invalid Redirect URI"}
	}

	// Set cookie, or deny: validates the session email and group
	// - for p.Validator see validator.go#newValidatorImpl for more info
	// - for p.provider.ValidateGroup see providers/google.go#ValidateGroup for more info
	if !p.Validator(session.Email) {
		log.Ctx(r.Context()).Error().Err(err).Str("email", session.Email).Msg("invalid email permissions denied")
		return "", httputil.HTTPError{Code: http.StatusForbidden, Message: "Invalid Account"}
	}
	log.Ctx(r.Context()).Info().Str("email", session.Email).Msg("authentication complete")
	err = p.sessionStore.SaveSession(w, r, session)
	if err != nil {
		log.Ctx(r.Context()).Error().Err(err).Msg("internal error")
		return "", httputil.HTTPError{Code: http.StatusInternalServerError, Message: "Internal Error"}
	}
	return redirect, nil
}

// OAuthCallback handles the callback from the provider, and returns an error response if there is an error.
// If there is no error it will redirect to the redirect url.
func (p *Authenticate) OAuthCallback(w http.ResponseWriter, r *http.Request) {
	redirect, err := p.getOAuthCallback(w, r)
	switch h := err.(type) {
	case nil:
		break
	case httputil.HTTPError:
		httputil.ErrorResponse(w, r, h.Message, h.Code)
		return
	default:
		httputil.ErrorResponse(w, r, "Internal Error", http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, redirect, http.StatusFound)
}

// Redeem has a signed access token, and provides the user information associated with the access token.
func (p *Authenticate) Redeem(w http.ResponseWriter, r *http.Request) {
	// The auth code is redeemed by the sso proxy for an access token, refresh token,
	// expiration, and email.
	// requestLog := log.WithRequest(req, "authenticate.Redeem")
	err := r.ParseForm()
	if err != nil {
		http.Error(w, fmt.Sprintf("Bad Request: %s", err.Error()), http.StatusBadRequest)
		return
	}

	session, err := sessions.UnmarshalSession(r.Form.Get("code"), p.cipher)
	if err != nil {
		log.Ctx(r.Context()).Error().Err(err).Int("http-status", http.StatusUnauthorized).Msg("invalid auth code")
		http.Error(w, fmt.Sprintf("invalid auth code: %s", err.Error()), http.StatusUnauthorized)
		return
	}

	if session == nil {
		log.Ctx(r.Context()).Error().Err(err).Int("http-status", http.StatusUnauthorized).Msg("invalid session")
		http.Error(w, fmt.Sprintf("invalid session: %s", err.Error()), http.StatusUnauthorized)
		return
	}

	if session != nil && (session.RefreshPeriodExpired() || session.LifetimePeriodExpired()) {
		log.Ctx(r.Context()).Error().Msg("expired session")
		p.sessionStore.ClearSession(w, r)
		http.Error(w, fmt.Sprintf("expired session"), http.StatusUnauthorized)
		return
	}

	response := struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		IDToken      string `json:"id_token"`
		ExpiresIn    int64  `json:"expires_in"`
		Email        string `json:"email"`
	}{
		AccessToken:  session.AccessToken,
		RefreshToken: session.RefreshToken,
		IDToken:      session.IDToken,
		ExpiresIn:    int64(session.RefreshDeadline.Sub(time.Now()).Seconds()),
		Email:        session.Email,
	}

	jsonBytes, err := json.Marshal(response)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	w.Header().Set("GAP-Auth", session.Email)
	w.Header().Set("Content-Type", "application/json")
	w.Write(jsonBytes)

}

// Refresh takes a refresh token and returns a new access token
func (p *Authenticate) Refresh(w http.ResponseWriter, r *http.Request) {
	err := r.ParseForm()
	if err != nil {
		http.Error(w, fmt.Sprintf("Bad Request: %s", err.Error()), http.StatusBadRequest)
		return
	}

	refreshToken := r.Form.Get("refresh_token")
	if refreshToken == "" {
		http.Error(w, "Bad Request: No Refresh Token", http.StatusBadRequest)
		return
	}

	accessToken, expiresIn, err := p.provider.RefreshAccessToken(refreshToken)
	if err != nil {
		httputil.ErrorResponse(w, r, err.Error(), httputil.CodeForError(err))
		return
	}

	response := struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int64  `json:"expires_in"`
	}{
		AccessToken: accessToken,
		ExpiresIn:   int64(expiresIn.Seconds()),
	}

	bytes, err := json.Marshal(response)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusCreated)
	w.Header().Set("Content-Type", "application/json")
	w.Write(bytes)
}

// GetProfile gets a list of groups of which a user is a member.
func (p *Authenticate) GetProfile(w http.ResponseWriter, r *http.Request) {
	// The sso proxy sends the user's email to this endpoint to get a list of Google groups that
	// the email is a member of. The proxy will compare these groups to the list of allowed
	// groups for the upstream service the user is trying to access.

	email := r.FormValue("email")
	if email == "" {
		http.Error(w, "no email address included", http.StatusBadRequest)
		return
	}

	// groupsFormValue := r.FormValue("groups")
	// allowedGroups := []string{}
	// if groupsFormValue != "" {
	// 	allowedGroups = strings.Split(groupsFormValue, ",")
	// }

	// groups, err := p.provider.ValidateGroupMembership(email, allowedGroups)
	// if err != nil {
	// 	log.Error().Err(err).Msg("authenticate.GetProfile : error retrieving groups")
	// 	httputil.ErrorResponse(w, r, err.Error(), httputil.CodeForError(err))
	// 	return
	// }

	response := struct {
		Email string `json:"email"`
	}{
		Email: email,
	}

	jsonBytes, err := json.Marshal(response)
	if err != nil {
		http.Error(w, fmt.Sprintf("error marshaling response: %s", err.Error()), http.StatusInternalServerError)
		return
	}
	w.Header().Set("GAP-Auth", email)
	w.Header().Set("Content-Type", "application/json")
	w.Write(jsonBytes)
}

// ValidateToken validates the X-Access-Token from the header and returns an error response
// if it's invalid
func (p *Authenticate) ValidateToken(w http.ResponseWriter, r *http.Request) {
	accessToken := r.Header.Get("X-Access-Token")
	idToken := r.Header.Get("X-Id-Token")

	if accessToken == "" {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	if idToken == "" {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	ok := p.provider.ValidateSessionState(&sessions.SessionState{
		AccessToken: accessToken,
		IDToken:     idToken,
	})

	if !ok {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	w.WriteHeader(http.StatusOK)
	return
}
