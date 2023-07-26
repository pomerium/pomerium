package proxy

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"

	"github.com/go-jose/go-jose/v3/jwt"
	"github.com/gorilla/mux"
	"google.golang.org/protobuf/encoding/protojson"

	"github.com/pomerium/pomerium/internal/handlers"
	"github.com/pomerium/pomerium/internal/httputil"
	"github.com/pomerium/pomerium/internal/middleware"
	"github.com/pomerium/pomerium/internal/urlutil"
	"github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/grpc/identity"
	"github.com/pomerium/pomerium/pkg/grpc/session"
	"github.com/pomerium/pomerium/pkg/grpc/user"
	"github.com/pomerium/pomerium/pkg/hpke"
)

// registerDashboardHandlers returns the proxy service's ServeMux
func (p *Proxy) registerDashboardHandlers(r *mux.Router) *mux.Router {
	h := httputil.DashboardSubrouter(r)
	h.Use(middleware.SetHeaders(httputil.HeadersContentSecurityPolicy))

	// special pomerium endpoints for users to view their session
	h.Path("/").Handler(httputil.HandlerFunc(p.userInfo)).Methods(http.MethodGet)
	h.Path("/device-enrolled").Handler(httputil.HandlerFunc(p.deviceEnrolled))
	h.Path("/jwt").Handler(httputil.HandlerFunc(p.jwtAssertion)).Methods(http.MethodGet)
	h.Path("/sign_out").Handler(httputil.HandlerFunc(p.SignOut)).Methods(http.MethodGet, http.MethodPost)
	h.Path("/webauthn").Handler(p.webauthn)

	// called following authenticate auth flow to grab a new or existing session
	// the route specific cookie is returned in a signed query params
	c := r.PathPrefix(dashboardPath + "/callback").Subrouter()
	c.Path("/").Handler(httputil.HandlerFunc(p.Callback)).Methods(http.MethodGet)

	// Programmatic API handlers and middleware
	a := r.PathPrefix(dashboardPath + "/api").Subrouter()
	// login api handler generates a user-navigable login url to authenticate
	a.Path("/v1/login").Handler(httputil.HandlerFunc(p.ProgrammaticLogin)).
		Queries(urlutil.QueryRedirectURI, "").
		Methods(http.MethodGet)

	return r
}

// RobotsTxt sets the User-Agent header in the response to be "Disallow"
func (p *Proxy) RobotsTxt(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, "User-agent: *\nDisallow: /")
}

// SignOut clears the local session and redirects the request to the sign out url.
// It's the responsibility of the authenticate service to revoke the remote session and clear
// the authenticate service's session state.
func (p *Proxy) SignOut(w http.ResponseWriter, r *http.Request) error {
	state := p.state.Load()

	var redirectURL *url.URL
	signOutURL, err := p.currentOptions.Load().GetSignOutRedirectURL()
	if err != nil {
		return httputil.NewError(http.StatusInternalServerError, err)
	}
	if signOutURL != nil {
		redirectURL = signOutURL
	}
	if uri, err := urlutil.ParseAndValidateURL(r.FormValue(urlutil.QueryRedirectURI)); err == nil && uri.String() != "" {
		redirectURL = uri
	}

	dashboardURL := state.authenticateDashboardURL.ResolveReference(&url.URL{
		Path: "/.pomerium/sign_out",
	})
	q := dashboardURL.Query()
	if redirectURL != nil {
		q.Set(urlutil.QueryRedirectURI, redirectURL.String())
	}
	dashboardURL.RawQuery = q.Encode()

	state.sessionStore.ClearSession(w, r)
	httputil.Redirect(w, r, urlutil.NewSignedURL(state.sharedKey, dashboardURL).String(), http.StatusFound)
	return nil
}

func (p *Proxy) userInfo(w http.ResponseWriter, r *http.Request) error {
	data, err := p.getUserInfoData(r)
	if err != nil {
		return err
	}
	handlers.UserInfo(data).ServeHTTP(w, r)
	return nil
}

func (p *Proxy) deviceEnrolled(w http.ResponseWriter, r *http.Request) error {
	data, err := p.getUserInfoData(r)
	if err != nil {
		return err
	}
	handlers.DeviceEnrolled(data).ServeHTTP(w, r)
	return nil
}

// Callback handles the result of a successful call to the authenticate service
// and is responsible setting per-route sessions.
func (p *Proxy) Callback(w http.ResponseWriter, r *http.Request) error {
	state := p.state.Load()
	options := p.currentOptions.Load()

	if err := r.ParseForm(); err != nil {
		return httputil.NewError(http.StatusBadRequest, err)
	}

	// decrypt the URL values
	senderPublicKey, values, err := hpke.DecryptURLValues(state.hpkePrivateKey, r.Form)
	if err != nil {
		return httputil.NewError(http.StatusBadRequest, fmt.Errorf("invalid encrypted query string: %w", err))
	}

	// confirm this request came from the authenticate service
	err = p.validateSenderPublicKey(r.Context(), senderPublicKey)
	if err != nil {
		return err
	}

	// validate that the request has not expired
	err = urlutil.ValidateTimeParameters(values)
	if err != nil {
		return httputil.NewError(http.StatusBadRequest, err)
	}

	profile, err := getProfileFromValues(values)
	if err != nil {
		return err
	}

	ss := newSessionStateFromProfile(profile)
	s, err := session.Get(r.Context(), state.dataBrokerClient, ss.ID)
	if err != nil {
		s = &session.Session{Id: ss.ID}
	}
	populateSessionFromProfile(s, profile, ss, options.CookieExpire)
	u, err := user.Get(r.Context(), state.dataBrokerClient, ss.UserID())
	if err != nil {
		u = &user.User{Id: ss.UserID()}
	}
	populateUserFromProfile(u, profile, ss)

	redirectURI, err := getRedirectURIFromValues(values)
	if err != nil {
		return err
	}

	// save the records
	res, err := state.dataBrokerClient.Put(r.Context(), &databroker.PutRequest{
		Records: []*databroker.Record{
			databroker.NewRecord(s),
			databroker.NewRecord(u),
		},
	})
	if err != nil {
		return httputil.NewError(http.StatusInternalServerError, fmt.Errorf("proxy: error saving databroker records: %w", err))
	}
	ss.DatabrokerServerVersion = res.GetServerVersion()
	for _, record := range res.GetRecords() {
		if record.GetVersion() > ss.DatabrokerRecordVersion {
			ss.DatabrokerRecordVersion = record.GetVersion()
		}
	}

	// save the session state
	rawJWT, err := state.encoder.Marshal(ss)
	if err != nil {
		return httputil.NewError(http.StatusInternalServerError, fmt.Errorf("proxy: error marshaling session state: %w", err))
	}
	if err = state.sessionStore.SaveSession(w, r, rawJWT); err != nil {
		return httputil.NewError(http.StatusInternalServerError, fmt.Errorf("proxy: error saving session state: %w", err))
	}

	// if programmatic, encode the session jwt as a query param
	if isProgrammatic := values.Get(urlutil.QueryIsProgrammatic); isProgrammatic == "true" {
		q := redirectURI.Query()
		q.Set(urlutil.QueryPomeriumJWT, string(rawJWT))
		redirectURI.RawQuery = q.Encode()
	}

	// redirect
	httputil.Redirect(w, r, redirectURI.String(), http.StatusFound)
	return nil
}

// ProgrammaticLogin returns a signed url that can be used to login
// using the authenticate service.
func (p *Proxy) ProgrammaticLogin(w http.ResponseWriter, r *http.Request) error {
	state := p.state.Load()
	options := p.currentOptions.Load()

	redirectURI, err := urlutil.ParseAndValidateURL(r.FormValue(urlutil.QueryRedirectURI))
	if err != nil {
		return httputil.NewError(http.StatusBadRequest, err)
	}

	if !urlutil.IsRedirectAllowed(redirectURI, state.programmaticRedirectDomainWhitelist) {
		return httputil.NewError(http.StatusBadRequest, errors.New("invalid redirect uri"))
	}

	idp, err := options.GetIdentityProviderForRequestURL(urlutil.GetAbsoluteURL(r).String())
	if err != nil {
		return httputil.NewError(http.StatusInternalServerError, err)
	}

	hpkeAuthenticateKey, err := state.authenticateKeyFetcher.FetchPublicKey(r.Context())
	if err != nil {
		return httputil.NewError(http.StatusInternalServerError, err)
	}

	signinURL := *state.authenticateSigninURL
	callbackURI := urlutil.GetAbsoluteURL(r)
	callbackURI.Path = dashboardPath + "/callback/"
	q := signinURL.Query()
	q.Set(urlutil.QueryCallbackURI, callbackURI.String())
	q.Set(urlutil.QueryIsProgrammatic, "true")
	signinURL.RawQuery = q.Encode()

	rawURL, err := urlutil.SignInURL(state.hpkePrivateKey, hpkeAuthenticateKey, &signinURL, redirectURI, idp.GetId())
	if err != nil {
		return httputil.NewError(http.StatusInternalServerError, err)
	}

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = io.WriteString(w, rawURL)
	return nil
}

// jwtAssertion returns the current request's JWT assertion (rfc7519#section-10.3.1).
func (p *Proxy) jwtAssertion(w http.ResponseWriter, r *http.Request) error {
	rawAssertionJWT := r.Header.Get(httputil.HeaderPomeriumJWTAssertion)
	if rawAssertionJWT == "" {
		return httputil.NewError(http.StatusNotFound, errors.New("jwt not found"))
	}

	assertionJWT, err := jwt.ParseSigned(rawAssertionJWT)
	if err != nil {
		return httputil.NewError(http.StatusNotFound, errors.New("jwt not found"))
	}

	var dst struct {
		Subject string `json:"sub"`
	}
	if assertionJWT.UnsafeClaimsWithoutVerification(&dst) != nil || dst.Subject == "" {
		return httputil.NewError(http.StatusUnauthorized, errors.New("jwt not found"))
	}

	w.Header().Set("Content-Type", "application/jwt")
	w.WriteHeader(http.StatusOK)
	_, _ = io.WriteString(w, rawAssertionJWT)
	return nil
}

func (p *Proxy) validateSenderPublicKey(ctx context.Context, senderPublicKey *hpke.PublicKey) error {
	state := p.state.Load()

	authenticatePublicKey, err := state.authenticateKeyFetcher.FetchPublicKey(ctx)
	if err != nil {
		return httputil.NewError(http.StatusInternalServerError, fmt.Errorf("hpke: error retrieving authenticate service public key: %w", err))
	}

	if !authenticatePublicKey.Equals(senderPublicKey) {
		return httputil.NewError(http.StatusBadRequest, fmt.Errorf("hpke: invalid authenticate service public key"))
	}

	return nil
}

func getProfileFromValues(values url.Values) (*identity.Profile, error) {
	rawProfile := values.Get(urlutil.QueryIdentityProfile)
	if rawProfile == "" {
		return nil, httputil.NewError(http.StatusBadRequest, fmt.Errorf("missing %s", urlutil.QueryIdentityProfile))
	}

	var profile identity.Profile
	err := protojson.Unmarshal([]byte(rawProfile), &profile)
	if err != nil {
		return nil, httputil.NewError(http.StatusBadRequest, fmt.Errorf("invalid %s: %w", urlutil.QueryIdentityProfile, err))
	}
	return &profile, nil
}

func getRedirectURIFromValues(values url.Values) (*url.URL, error) {
	rawRedirectURI := values.Get(urlutil.QueryRedirectURI)
	if rawRedirectURI == "" {
		return nil, httputil.NewError(http.StatusBadRequest, fmt.Errorf("missing %s", urlutil.QueryRedirectURI))
	}
	redirectURI, err := urlutil.ParseAndValidateURL(rawRedirectURI)
	if err != nil {
		return nil, httputil.NewError(http.StatusBadRequest, fmt.Errorf("invalid %s: %w", urlutil.QueryRedirectURI, err))
	}
	return redirectURI, nil
}
