package authenticate // import "github.com/pomerium/pomerium/authenticate"

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/pomerium/pomerium/internal/aead"
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
func (p *Authenticator) Handler() http.Handler {
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

	return m.SetHeaders(mux, securityHeaders)
}

// validateSignature wraps a common collection of middlewares to validate signatures
func (p *Authenticator) validateSignature(f http.HandlerFunc) http.HandlerFunc {
	return validateRedirectURI(validateSignature(f, p.SharedKey), p.ProxyRootDomains)

}

// validateSignature wraps a common collection of middlewares to validate
// a (presumably) existing user session
func (p *Authenticator) validateExisting(f http.HandlerFunc) http.HandlerFunc {
	return m.ValidateClientSecret(f, p.SharedKey)
}

// RobotsTxt handles the /robots.txt route.
func (p *Authenticator) RobotsTxt(rw http.ResponseWriter, req *http.Request) {
	rw.WriteHeader(http.StatusOK)
	fmt.Fprintf(rw, "User-agent: *\nDisallow: /")
}

// PingPage handles the /ping route
func (p *Authenticator) PingPage(rw http.ResponseWriter, req *http.Request) {
	rw.WriteHeader(http.StatusOK)
	fmt.Fprintf(rw, "OK")
}

// SignInPage directs the user to the sign in page. Takes a `redirect_uri` param.
func (p *Authenticator) SignInPage(rw http.ResponseWriter, req *http.Request) {
	requestLog := log.WithRequest(req, "authenticate.SignInPage")
	redirectURL := p.RedirectURL.ResolveReference(req.URL)
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
	requestLog.Info().
		Str("ProviderName", p.provider.Data().ProviderName).
		Str("Redirect", redirectURL.String()).
		Str("Destination", destinationURL.Host).
		Str("AllowedDomains", strings.Join(p.AllowedDomains, ", ")).
		Msg("authenticate.SignInPage")
	rw.WriteHeader(http.StatusOK)
	p.templates.ExecuteTemplate(rw, "sign_in.html", t)
}

func (p *Authenticator) authenticate(rw http.ResponseWriter, req *http.Request) (*sessions.SessionState, error) {
	requestLog := log.WithRequest(req, "authenticate.authenticate")
	session, err := p.sessionStore.LoadSession(req)
	if err != nil {
		log.Error().Err(err).Msg("authenticate.authenticate")
		p.sessionStore.ClearSession(rw, req)
		return nil, err
	}

	// ensure sessions lifetime has not expired
	if session.LifetimePeriodExpired() {
		requestLog.Warn().Msg("lifetime expired")
		p.sessionStore.ClearSession(rw, req)
		return nil, sessions.ErrLifetimeExpired
	}
	// check if session refresh period is up
	if session.RefreshPeriodExpired() {
		ok, err := p.provider.RefreshSessionIfNeeded(session)
		if err != nil {
			requestLog.Error().Err(err).Msg("failed to refresh session")
			p.sessionStore.ClearSession(rw, req)
			return nil, err
		}
		if !ok {
			requestLog.Error().Msg("user unauthorized after refresh")
			p.sessionStore.ClearSession(rw, req)
			return nil, httputil.ErrUserNotAuthorized
		}
		// update refresh'd session in cookie
		err = p.sessionStore.SaveSession(rw, req, session)
		if err != nil {
			// We refreshed the session successfully, but failed to save it.
			// This could be from failing to encode the session properly.
			// But, we clear the session cookie and reject the request
			requestLog.Error().Err(err).Msg("could not save refreshed session")
			p.sessionStore.ClearSession(rw, req)
			return nil, err
		}
	} else {
		// The session has not exceeded it's lifetime or requires refresh
		ok := p.provider.ValidateSessionState(session)
		if !ok {
			requestLog.Error().Msg("invalid session state")
			p.sessionStore.ClearSession(rw, req)
			return nil, httputil.ErrUserNotAuthorized
		}
		err = p.sessionStore.SaveSession(rw, req, session)
		if err != nil {
			requestLog.Error().Err(err).Msg("failed to save valid session")
			p.sessionStore.ClearSession(rw, req)
			return nil, err
		}
	}

	if !p.Validator(session.Email) {
		requestLog.Error().Msg("invalid email user")
		return nil, httputil.ErrUserNotAuthorized
	}
	return session, nil
}

// SignIn handles the /sign_in endpoint. It attempts to authenticate the user,
// and if the user is not authenticated, it renders a sign in page.
func (p *Authenticator) SignIn(rw http.ResponseWriter, req *http.Request) {
	// We attempt to authenticate the user. If they cannot be authenticated, we render a sign-in
	// page.
	//
	// If the user is authenticated, we redirect back to the proxy application
	// at the `redirect_uri`, with a temporary token.
	//
	// TODO: It is possible for a user to visit this page without a redirect destination.
	// Should we allow the user to authenticate? If not, what should be the proposed workflow?

	session, err := p.authenticate(rw, req)
	switch err {
	case nil:
		// User is authenticated, redirect back to the proxy application
		// with the necessary state
		p.ProxyOAuthRedirect(rw, req, session)
	case http.ErrNoCookie:
		log.Error().Err(err).Msg("authenticate.SignIn : err no cookie")
		p.SignInPage(rw, req)
	case sessions.ErrLifetimeExpired, sessions.ErrInvalidSession:
		log.Error().Err(err).Msg("authenticate.SignIn : invalid cookie cookie")
		p.sessionStore.ClearSession(rw, req)
		p.SignInPage(rw, req)
	default:
		log.Error().Err(err).Msg("authenticate.SignIn : unknown error cookie")
		httputil.ErrorResponse(rw, req, err.Error(), httputil.CodeForError(err))
	}
}

// ProxyOAuthRedirect redirects the user back to sso proxy's redirection endpoint.
func (p *Authenticator) ProxyOAuthRedirect(rw http.ResponseWriter, req *http.Request, session *sessions.SessionState) {
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

	err := req.ParseForm()
	if err != nil {
		httputil.ErrorResponse(rw, req, err.Error(), http.StatusInternalServerError)
		return
	}

	state := req.Form.Get("state")
	if state == "" {
		httputil.ErrorResponse(rw, req, "no state parameter supplied", http.StatusForbidden)
		return
	}

	redirectURI := req.Form.Get("redirect_uri")
	if redirectURI == "" {
		httputil.ErrorResponse(rw, req, "no redirect_uri parameter supplied", http.StatusForbidden)
		return
	}

	redirectURL, err := url.Parse(redirectURI)
	if err != nil {
		httputil.ErrorResponse(rw, req, "malformed redirect_uri parameter passed", http.StatusBadRequest)
		return
	}

	encrypted, err := sessions.MarshalSession(session, p.cipher)
	if err != nil {
		httputil.ErrorResponse(rw, req, err.Error(), http.StatusInternalServerError)
		return
	}
	http.Redirect(rw, req, getAuthCodeRedirectURL(redirectURL, state, string(encrypted)), http.StatusFound)
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
func (p *Authenticator) SignOut(rw http.ResponseWriter, req *http.Request) {
	redirectURI := req.Form.Get("redirect_uri")
	if req.Method == "GET" {
		p.SignOutPage(rw, req, "")
		return
	}

	session, err := p.sessionStore.LoadSession(req)
	switch err {
	case nil:
		break
	case http.ErrNoCookie: // if there's no cookie in the session we can just redirect
		http.Redirect(rw, req, redirectURI, http.StatusFound)
		return
	default:
		// a different error, clear the session cookie and redirect
		log.Error().Err(err).Msg("authenticate.SignOut : error loading cookie session")
		p.sessionStore.ClearSession(rw, req)
		http.Redirect(rw, req, redirectURI, http.StatusFound)
		return
	}

	err = p.provider.Revoke(session)
	if err != nil {
		log.Error().Err(err).Msg("authenticate.SignOut : error revoking session")
		p.SignOutPage(rw, req, "An error occurred during sign out. Please try again.")
		return
	}
	p.sessionStore.ClearSession(rw, req)
	http.Redirect(rw, req, redirectURI, http.StatusFound)
}

// SignOutPage renders a sign out page with a message
func (p *Authenticator) SignOutPage(rw http.ResponseWriter, req *http.Request, message string) {
	// validateRedirectURI middleware already ensures that this is a valid URL
	redirectURI := req.Form.Get("redirect_uri")
	session, err := p.sessionStore.LoadSession(req)
	if err != nil {
		http.Redirect(rw, req, redirectURI, http.StatusFound)
		return
	}

	signature := req.Form.Get("sig")
	timestamp := req.Form.Get("ts")
	destinationURL, _ := url.Parse(redirectURI)

	// An error message indicates that an internal server error occurred
	if message != "" {
		rw.WriteHeader(http.StatusInternalServerError)
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
	p.templates.ExecuteTemplate(rw, "sign_out.html", t)
	return
}

// OAuthStart starts the authentication process by redirecting to the provider. It provides a
// `redirectURI`, allowing the provider to redirect back to the sso proxy after authentication.
func (p *Authenticator) OAuthStart(rw http.ResponseWriter, req *http.Request) {

	nonce := fmt.Sprintf("%x", aead.GenerateKey())
	p.csrfStore.SetCSRF(rw, req, nonce)

	authRedirectURL, err := url.Parse(req.URL.Query().Get("redirect_uri"))
	if err != nil || !validRedirectURI(authRedirectURL.String(), p.ProxyRootDomains) {
		httputil.ErrorResponse(rw, req, "Invalid redirect parameter", http.StatusBadRequest)
		return
	}

	proxyRedirectURL, err := url.Parse(authRedirectURL.Query().Get("redirect_uri"))
	if err != nil || !validRedirectURI(proxyRedirectURL.String(), p.ProxyRootDomains) {
		httputil.ErrorResponse(rw, req, "Invalid redirect parameter", http.StatusBadRequest)
		return
	}

	proxyRedirectSig := authRedirectURL.Query().Get("sig")
	ts := authRedirectURL.Query().Get("ts")
	if !validSignature(proxyRedirectURL.String(), proxyRedirectSig, ts, p.SharedKey) {
		httputil.ErrorResponse(rw, req, "Invalid redirect parameter", http.StatusBadRequest)
		return
	}

	state := base64.URLEncoding.EncodeToString([]byte(fmt.Sprintf("%v:%v", nonce, authRedirectURL.String())))

	signInURL := p.provider.GetSignInURL(state)

	http.Redirect(rw, req, signInURL, http.StatusFound)
}

func (p *Authenticator) redeemCode(host, code string) (*sessions.SessionState, error) {
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
func (p *Authenticator) getOAuthCallback(rw http.ResponseWriter, req *http.Request) (string, error) {
	requestLog := log.WithRequest(req, "authenticate.getOAuthCallback")
	// finish the oauth cycle
	err := req.ParseForm()
	if err != nil {
		return "", httputil.HTTPError{Code: http.StatusInternalServerError, Message: err.Error()}
	}
	errorString := req.Form.Get("error")
	if errorString != "" {
		return "", httputil.HTTPError{Code: http.StatusForbidden, Message: errorString}
	}
	code := req.Form.Get("code")
	if code == "" {
		return "", httputil.HTTPError{Code: http.StatusBadRequest, Message: "Missing Code"}
	}

	session, err := p.redeemCode(req.Host, code)
	if err != nil {
		requestLog.Error().Err(err).Msg("error redeeming authentication code")
		return "", err
	}

	bytes, err := base64.URLEncoding.DecodeString(req.Form.Get("state"))
	if err != nil {
		return "", httputil.HTTPError{Code: http.StatusInternalServerError, Message: "Invalid State"}
	}
	s := strings.SplitN(string(bytes), ":", 2)
	if len(s) != 2 {
		return "", httputil.HTTPError{Code: http.StatusInternalServerError, Message: "Invalid State"}
	}
	nonce := s[0]
	redirect := s[1]
	c, err := p.csrfStore.GetCSRF(req)
	if err != nil {
		return "", httputil.HTTPError{Code: http.StatusForbidden, Message: "Missing CSRF token"}
	}
	p.csrfStore.ClearCSRF(rw, req)
	if c.Value != nonce {
		requestLog.Error().Err(err).Msg("csrf token mismatch")
		return "", httputil.HTTPError{Code: http.StatusForbidden, Message: "csrf failed"}
	}

	if !validRedirectURI(redirect, p.ProxyRootDomains) {
		return "", httputil.HTTPError{Code: http.StatusForbidden, Message: "Invalid Redirect URI"}
	}

	// Set cookie, or deny: The authenticator validates the session email and group
	// - for p.Validator see validator.go#newValidatorImpl for more info
	// - for p.provider.ValidateGroup see providers/google.go#ValidateGroup for more info
	if !p.Validator(session.Email) {
		requestLog.Error().Err(err).Str("email", session.Email).Msg("invalid email permissions denied")
		return "", httputil.HTTPError{Code: http.StatusForbidden, Message: "Invalid Account"}
	}
	requestLog.Info().Str("email", session.Email).Msg("authentication complete")
	err = p.sessionStore.SaveSession(rw, req, session)
	if err != nil {
		requestLog.Error().Err(err).Msg("internal error")
		return "", httputil.HTTPError{Code: http.StatusInternalServerError, Message: "Internal Error"}
	}
	return redirect, nil
}

// OAuthCallback handles the callback from the provider, and returns an error response if there is an error.
// If there is no error it will redirect to the redirect url.
func (p *Authenticator) OAuthCallback(rw http.ResponseWriter, req *http.Request) {
	redirect, err := p.getOAuthCallback(rw, req)
	switch h := err.(type) {
	case nil:
		break
	case httputil.HTTPError:
		httputil.ErrorResponse(rw, req, h.Message, h.Code)
		return
	default:
		httputil.ErrorResponse(rw, req, "Internal Error", http.StatusInternalServerError)
		return
	}
	http.Redirect(rw, req, redirect, http.StatusFound)
}

// Redeem has a signed access token, and provides the user information associated with the access token.
func (p *Authenticator) Redeem(rw http.ResponseWriter, req *http.Request) {
	// The auth code is redeemed by the sso proxy for an access token, refresh token,
	// expiration, and email.
	requestLog := log.WithRequest(req, "authenticate.Redeem")
	err := req.ParseForm()
	if err != nil {
		http.Error(rw, fmt.Sprintf("Bad Request: %s", err.Error()), http.StatusBadRequest)
		return
	}

	session, err := sessions.UnmarshalSession(req.Form.Get("code"), p.cipher)
	if err != nil {
		requestLog.Error().Err(err).Int("http-status", http.StatusUnauthorized).Msg("invalid auth code")
		http.Error(rw, fmt.Sprintf("invalid auth code: %s", err.Error()), http.StatusUnauthorized)
		return
	}

	if session == nil {
		requestLog.Error().Err(err).Int("http-status", http.StatusUnauthorized).Msg("invalid session")
		http.Error(rw, fmt.Sprintf("invalid session: %s", err.Error()), http.StatusUnauthorized)
		return
	}

	if session != nil && (session.RefreshPeriodExpired() || session.LifetimePeriodExpired()) {
		requestLog.Error().Msg("expired session")
		p.sessionStore.ClearSession(rw, req)
		http.Error(rw, fmt.Sprintf("expired session"), http.StatusUnauthorized)
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
		rw.WriteHeader(http.StatusInternalServerError)
		return
	}
	rw.Header().Set("GAP-Auth", session.Email)
	rw.Header().Set("Content-Type", "application/json")
	rw.Write(jsonBytes)

}

// Refresh takes a refresh token and returns a new access token
func (p *Authenticator) Refresh(rw http.ResponseWriter, req *http.Request) {
	err := req.ParseForm()
	if err != nil {
		http.Error(rw, fmt.Sprintf("Bad Request: %s", err.Error()), http.StatusBadRequest)
		return
	}

	refreshToken := req.Form.Get("refresh_token")
	if refreshToken == "" {
		http.Error(rw, "Bad Request: No Refresh Token", http.StatusBadRequest)
		return
	}

	accessToken, expiresIn, err := p.provider.RefreshAccessToken(refreshToken)
	if err != nil {
		httputil.ErrorResponse(rw, req, err.Error(), httputil.CodeForError(err))
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
		rw.WriteHeader(http.StatusInternalServerError)
		return
	}

	rw.WriteHeader(http.StatusCreated)
	rw.Header().Set("Content-Type", "application/json")
	rw.Write(bytes)
}

// GetProfile gets a list of groups of which a user is a member.
func (p *Authenticator) GetProfile(rw http.ResponseWriter, req *http.Request) {
	// The sso proxy sends the user's email to this endpoint to get a list of Google groups that
	// the email is a member of. The proxy will compare these groups to the list of allowed
	// groups for the upstream service the user is trying to access.

	email := req.FormValue("email")
	if email == "" {
		http.Error(rw, "no email address included", http.StatusBadRequest)
		return
	}

	// groupsFormValue := req.FormValue("groups")
	// allowedGroups := []string{}
	// if groupsFormValue != "" {
	// 	allowedGroups = strings.Split(groupsFormValue, ",")
	// }

	// groups, err := p.provider.ValidateGroupMembership(email, allowedGroups)
	// if err != nil {
	// 	log.Error().Err(err).Msg("authenticate.GetProfile : error retrieving groups")
	// 	httputil.ErrorResponse(rw, req, err.Error(), httputil.CodeForError(err))
	// 	return
	// }

	response := struct {
		Email string `json:"email"`
	}{
		Email: email,
	}

	jsonBytes, err := json.Marshal(response)
	if err != nil {
		http.Error(rw, fmt.Sprintf("error marshaling response: %s", err.Error()), http.StatusInternalServerError)
		return
	}
	rw.Header().Set("GAP-Auth", email)
	rw.Header().Set("Content-Type", "application/json")
	rw.Write(jsonBytes)
}

// ValidateToken validates the X-Access-Token from the header and returns an error response
// if it's invalid
func (p *Authenticator) ValidateToken(rw http.ResponseWriter, req *http.Request) {
	accessToken := req.Header.Get("X-Access-Token")
	idToken := req.Header.Get("X-Id-Token")

	if accessToken == "" {
		rw.WriteHeader(http.StatusBadRequest)
		return
	}
	if idToken == "" {
		rw.WriteHeader(http.StatusBadRequest)
		return
	}

	ok := p.provider.ValidateSessionState(&sessions.SessionState{
		AccessToken: accessToken,
		IDToken:     idToken,
	})

	if !ok {
		rw.WriteHeader(http.StatusUnauthorized)
		return
	}

	rw.WriteHeader(http.StatusOK)
	return
}
