package proxy // import "github.com/pomerium/pomerium/proxy"

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"net/url"
	"reflect"
	"strings"
	"time"

	"github.com/pomerium/pomerium/internal/cryptutil"
	"github.com/pomerium/pomerium/internal/httputil"
	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/internal/middleware"
	"github.com/pomerium/pomerium/internal/policy"
	"github.com/pomerium/pomerium/internal/sessions"
)

// StateParameter holds the redirect id along with the session id.
type StateParameter struct {
	SessionID   string `json:"session_id"`
	RedirectURI string `json:"redirect_uri"`
}

// Handler returns a http handler for a Proxy
func (p *Proxy) Handler() http.Handler {
	// validation middleware chain
	validate := middleware.NewChain()
	validate = validate.Append(middleware.ValidateHost(func(host string) bool {
		_, ok := p.routeConfigs[host]
		return ok
	}))
	mux := http.NewServeMux()
	mux.HandleFunc("/robots.txt", p.RobotsTxt)
	mux.HandleFunc("/.pomerium/sign_out", p.SignOut)
	mux.HandleFunc("/.pomerium/callback", p.OAuthCallback)
	// mux.HandleFunc("/.pomerium/refresh", p.Refresh) //todo(bdd): needs DoS protection before inclusion
	mux.HandleFunc("/", p.Proxy)
	return validate.Then(mux)
}

// RobotsTxt sets the User-Agent header in the response to be "Disallow"
func (p *Proxy) RobotsTxt(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, "User-agent: *\nDisallow: /")
}

// SignOut redirects the request to the sign out url. It's the responsibility
// of the authenticate service to revoke the remote session and clear
// the local session state.
func (p *Proxy) SignOut(w http.ResponseWriter, r *http.Request) {
	redirectURL := &url.URL{
		Scheme: "https",
		Host:   r.Host,
		Path:   "/",
	}
	fullURL := p.GetSignOutURL(p.AuthenticateURL, redirectURL)
	http.Redirect(w, r, fullURL.String(), http.StatusFound)
}

// OAuthStart begins the authenticate flow, encrypting the redirect url
// in a request to the provider's sign in endpoint.
func (p *Proxy) OAuthStart(w http.ResponseWriter, r *http.Request) {
	requestURI := r.URL.String()
	callbackURL := p.GetRedirectURL(r.Host)

	// state prevents cross site forgery and maintain state across the client and server
	state := &StateParameter{
		SessionID:   fmt.Sprintf("%x", cryptutil.GenerateKey()), // nonce
		RedirectURI: requestURI,                                 // where to redirect the user back to
	}

	// we encrypt this value to be opaque the browser cookie
	// this value will be unique since we always use a randomized nonce as part of marshaling
	encryptedCSRF, err := p.cipher.Marshal(state)
	if err != nil {
		log.FromRequest(r).Error().Err(err).Msg("proxy: failed to marshal csrf")
		httputil.ErrorResponse(w, r, err.Error(), http.StatusInternalServerError)
		return
	}
	p.csrfStore.SetCSRF(w, r, encryptedCSRF)

	// we encrypt this value to be opaque the uri query value
	// this value will be unique since we always use a randomized nonce as part of marshaling
	encryptedState, err := p.cipher.Marshal(state)
	if err != nil {
		log.FromRequest(r).Error().Err(err).Msg("proxy: failed to encrypt cookie")
		httputil.ErrorResponse(w, r, err.Error(), http.StatusInternalServerError)
		return
	}
	signinURL := p.GetSignInURL(p.AuthenticateURL, callbackURL, encryptedState)
	log.FromRequest(r).Info().Str("SigninURL", signinURL.String()).Msg("proxy: oauth start")
	// redirect the user to the authenticate provider along with the encrypted state which
	// contains a redirect uri pointing back to the proxy
	http.Redirect(w, r, signinURL.String(), http.StatusFound)
}

// OAuthCallback validates the cookie sent back from the authenticate service. This function will
// contain an error, or it will contain a `code`; the code can be used to fetch an access token, and
// other metadata, from the authenticator.
// finish the oauth cycle
func (p *Proxy) OAuthCallback(w http.ResponseWriter, r *http.Request) {
	err := r.ParseForm()
	if err != nil {
		log.FromRequest(r).Error().Err(err).Msg("proxy: failed parsing request form")
		httputil.ErrorResponse(w, r, err.Error(), http.StatusInternalServerError)
		return
	}
	errorString := r.Form.Get("error")
	if errorString != "" {
		httputil.ErrorResponse(w, r, errorString, http.StatusForbidden)
		return
	}
	// We begin the process of redeeming the code for an access token.
	session, err := p.AuthenticateClient.Redeem(r.Context(), r.Form.Get("code"))
	if err != nil {
		log.FromRequest(r).Error().Err(err).Msg("proxy: error redeeming authorization code")
		httputil.ErrorResponse(w, r, "Internal error", http.StatusInternalServerError)
		return
	}

	encryptedState := r.Form.Get("state")
	stateParameter := &StateParameter{}
	err = p.cipher.Unmarshal(encryptedState, stateParameter)
	if err != nil {
		log.FromRequest(r).Error().Err(err).Msg("proxy: could not unmarshal state")
		httputil.ErrorResponse(w, r, "Internal error", http.StatusInternalServerError)
		return
	}

	c, err := p.csrfStore.GetCSRF(r)
	if err != nil {
		log.FromRequest(r).Error().Err(err).Msg("proxy: failed parsing csrf cookie")
		httputil.ErrorResponse(w, r, err.Error(), http.StatusBadRequest)
		return
	}
	p.csrfStore.ClearCSRF(w, r)

	encryptedCSRF := c.Value
	csrfParameter := &StateParameter{}
	err = p.cipher.Unmarshal(encryptedCSRF, csrfParameter)
	if err != nil {
		log.FromRequest(r).Error().Err(err).Msg("proxy: couldn't unmarshal CSRF")
		httputil.ErrorResponse(w, r, "Internal error", http.StatusInternalServerError)
		return
	}
	if encryptedState == encryptedCSRF {
		log.FromRequest(r).Error().Msg("encrypted state and CSRF should not be equal")
		httputil.ErrorResponse(w, r, "Bad request", http.StatusBadRequest)
		return
	}
	if !reflect.DeepEqual(stateParameter, csrfParameter) {
		log.FromRequest(r).Error().Msg("state and CSRF should be equal")
		httputil.ErrorResponse(w, r, "Bad request", http.StatusBadRequest)
		return
	}

	// We store the session in a cookie and redirect the user back to the application
	err = p.sessionStore.SaveSession(w, r, session)
	if err != nil {
		log.FromRequest(r).Error().Msg("error saving session")
		httputil.ErrorResponse(w, r, "Error saving session", http.StatusInternalServerError)
		return
	}

	log.FromRequest(r).Debug().
		Str("code", r.Form.Get("code")).
		Str("state", r.Form.Get("state")).
		Str("RefreshToken", session.RefreshToken).
		Str("session", session.AccessToken).
		Str("RedirectURI", stateParameter.RedirectURI).
		Msg("session")

	// This is the redirect back to the original requested application
	http.Redirect(w, r, stateParameter.RedirectURI, http.StatusFound)
}

// shouldSkipAuthentication contains conditions for skipping authentication.
// Conditions should be few in number and have strong justifications.
func (p *Proxy) shouldSkipAuthentication(r *http.Request) bool {
	pol, foundPolicy := p.policy(r)

	if isCORSPreflight(r) && foundPolicy && pol.CORSAllowPreflight {
		log.FromRequest(r).Debug().Msg("proxy: skipping authentication for valid CORS preflight request")
		return true
	}

	if foundPolicy && pol.AllowPublicUnauthenticatedAccess {
		log.FromRequest(r).Debug().Msg("proxy: skipping authentication for public route")
		return true
	}

	return false
}

// isCORSPreflight inspects the request to see if this is a valid CORS preflight request.
// These checks are not exhaustive, because the proxied server should be verifying it as well.
//
// See https://www.html5rocks.com/static/images/cors_server_flowchart.png for more info.
func isCORSPreflight(r *http.Request) bool {
	return r.Method == http.MethodOptions &&
		r.Header.Get("Access-Control-Request-Method") != "" &&
		r.Header.Get("Origin") != ""
}

// Proxy authenticates a request, either proxying the request if it is authenticated,
// or starting the authenticate service for validation if not.
func (p *Proxy) Proxy(w http.ResponseWriter, r *http.Request) {
	if !p.shouldSkipAuthentication(r) {
		session, err := p.sessionStore.LoadSession(r)
		if err != nil {
			switch err {
			case http.ErrNoCookie, sessions.ErrLifetimeExpired, sessions.ErrInvalidSession:
				log.FromRequest(r).Debug().Err(err).Msg("proxy: invalid session")
				p.sessionStore.ClearSession(w, r)
				p.OAuthStart(w, r)
				return
			default:
				log.FromRequest(r).Error().Err(err).Msg("proxy: unexpected error")
				httputil.ErrorResponse(w, r, "An unexpected error occurred", http.StatusInternalServerError)
				return
			}
		}

		err = p.authenticate(w, r, session)
		if err != nil {
			p.sessionStore.ClearSession(w, r)
			log.Debug().Err(err).Msg("proxy: user unauthenticated")
			httputil.ErrorResponse(w, r, "User unauthenticated", http.StatusForbidden)
			return
		}
		authorized, err := p.AuthorizeClient.Authorize(r.Context(), r.Host, session)
		if err != nil || !authorized {
			log.FromRequest(r).Warn().Err(err).Msg("proxy: user unauthorized")
			httputil.ErrorResponse(w, r, "Access unauthorized", http.StatusForbidden)
			return
		}
		// append
		r.Header.Set(HeaderUserID, session.User)
		r.Header.Set(HeaderEmail, session.Email)
		r.Header.Set(HeaderGroups, strings.Join(session.Groups, ","))
	}

	// We have validated the users request and now proxy their request to the provided upstream.
	route, ok := p.router(r)
	if !ok {
		httputil.ErrorResponse(w, r, "unknown route to proxy", http.StatusNotFound)
		return
	}
	route.ServeHTTP(w, r)
}

// Refresh refreshes a user session, validating group, extending timeout period, without requiring
// a user to re-authenticate
// func (p *Proxy) Refresh(w http.ResponseWriter, r *http.Request) {
// 	session, err := p.sessionStore.LoadSession(r)
// 	if err != nil {
// 		httputil.ErrorResponse(w, r, err.Error(), http.StatusInternalServerError)
// 		return
// 	}
// 	session, err = p.AuthenticateClient.Refresh(r.Context(), session)
// 	if err != nil {
// 		log.FromRequest(r).Warn().Err(err).Msg("proxy: refresh failed")
// 		httputil.ErrorResponse(w, r, err.Error(), http.StatusInternalServerError)
// 		return
// 	}
// 	err = p.sessionStore.SaveSession(w, r, session)
// 	if err != nil {
// 		httputil.ErrorResponse(w, r, err.Error(), http.StatusInternalServerError)
// 		return
// 	}
// 	w.WriteHeader(http.StatusOK)
// 	jsonSession, err := json.Marshal(session)
// 	if err != nil {
// 		httputil.ErrorResponse(w, r, err.Error(), http.StatusInternalServerError)
// 		return
// 	}
// 	fmt.Fprint(w, string(jsonSession))
// }

// Authenticate authenticates a request by checking for a session cookie, and validating its expiration,
// clearing the session cookie if it's invalid and returning an error if necessary..
func (p *Proxy) authenticate(w http.ResponseWriter, r *http.Request, session *sessions.SessionState) error {
	if session.RefreshPeriodExpired() {
		session, err := p.AuthenticateClient.Refresh(r.Context(), session)
		if err != nil {
			return fmt.Errorf("proxy: session refresh failed : %v", err)
		}
		err = p.sessionStore.SaveSession(w, r, session)
		if err != nil {
			return fmt.Errorf("proxy: refresh failed : %v", err)
		}
	} else {
		valid, err := p.AuthenticateClient.Validate(r.Context(), session.IDToken)
		if err != nil || !valid {
			return fmt.Errorf("proxy: session valid: %v : %v", valid, err)
		}
	}
	return nil
}

// Handle constructs a route from the given host string and matches it to the provided http.Handler and UpstreamConfig
func (p *Proxy) Handle(host string, handler http.Handler, pol *policy.Policy) {
	p.routeConfigs[host] = &routeConfig{
		mux:    handler,
		policy: *pol,
	}
}

// router attempts to find a route for a request. If a route is successfully matched,
// it returns the route information and a bool value of `true`. If a route can not be matched,
// a nil value for the route and false bool value is returned.
func (p *Proxy) router(r *http.Request) (http.Handler, bool) {
	config, ok := p.routeConfigs[r.Host]
	if ok {
		return config.mux, true
	}
	return nil, false
}

// policy attempts to find a policy for a request. If a policy is successfully matched,
// it returns the policy information and a bool value of `true`. If a policy can not be matched,
// a nil value for the policy and false bool value is returned.
func (p *Proxy) policy(r *http.Request) (*policy.Policy, bool) {
	config, ok := p.routeConfigs[r.Host]
	if ok {
		return &config.policy, true
	}
	return nil, false
}

// GetRedirectURL returns the redirect url for a single reverse proxy host. HTTPS is set explicitly.
func (p *Proxy) GetRedirectURL(host string) *url.URL {
	u := p.redirectURL
	u.Scheme = "https"
	u.Host = host
	return u
}

// signRedirectURL takes a redirect url string and timestamp and returns the base64
// encoded HMAC result.
func (p *Proxy) signRedirectURL(rawRedirect string, timestamp time.Time) string {
	data := []byte(fmt.Sprint(rawRedirect, timestamp.Unix()))
	h := cryptutil.Hash(p.SharedKey, data)
	return base64.URLEncoding.EncodeToString(h)
}

// GetSignInURL with typical oauth parameters
func (p *Proxy) GetSignInURL(authenticateURL, redirectURL *url.URL, state string) *url.URL {
	a := authenticateURL.ResolveReference(&url.URL{Path: "/sign_in"})
	now := time.Now()
	rawRedirect := redirectURL.String()
	params, _ := url.ParseQuery(a.RawQuery)
	params.Set("redirect_uri", rawRedirect)
	params.Set("shared_secret", p.SharedKey)
	params.Set("response_type", "code")
	params.Add("state", state)
	params.Set("ts", fmt.Sprint(now.Unix()))
	params.Set("sig", p.signRedirectURL(rawRedirect, now))
	a.RawQuery = params.Encode()
	return a
}

// GetSignOutURL creates and returns the sign out URL, given a redirectURL
func (p *Proxy) GetSignOutURL(authenticateURL, redirectURL *url.URL) *url.URL {
	a := authenticateURL.ResolveReference(&url.URL{Path: "/sign_out"})
	now := time.Now()
	rawRedirect := redirectURL.String()
	params, _ := url.ParseQuery(a.RawQuery)
	params.Add("redirect_uri", rawRedirect)
	params.Set("ts", fmt.Sprint(now.Unix()))
	params.Set("sig", p.signRedirectURL(rawRedirect, now))
	a.RawQuery = params.Encode()
	return a
}

func extendDeadline(ttl time.Duration) time.Time {
	return time.Now().Add(ttl).Truncate(time.Second)
}
