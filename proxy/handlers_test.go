package proxy

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/pomerium/pomerium/internal/version"
)

func TestProxy_RobotsTxt(t *testing.T) {
	proxy := Proxy{}
	req := httptest.NewRequest("GET", "/robots.txt", nil)
	rr := httptest.NewRecorder()
	proxy.RobotsTxt(rr, req)
	if status := rr.Code; status != http.StatusOK {
		t.Errorf("handler returned wrong status code: got %v want %v", status, http.StatusOK)
	}
	expected := fmt.Sprintf("User-agent: *\nDisallow: /")
	if rr.Body.String() != expected {
		t.Errorf("handler returned wrong body: got %v want %v", rr.Body.String(), expected)
	}
}

func TestProxy_GetRedirectURL(t *testing.T) {

	tests := []struct {
		name string
		host string
		want *url.URL
	}{
		{"google", "google.com", &url.URL{Scheme: "https", Host: "google.com", Path: "/.pomerium/callback"}},
		{"pomerium", "pomerium.io", &url.URL{Scheme: "https", Host: "pomerium.io", Path: "/.pomerium/callback"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &Proxy{redirectURL: &url.URL{Path: "/.pomerium/callback"}}

			if got := p.GetRedirectURL(tt.host); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Proxy.GetRedirectURL() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestProxy_signRedirectURL(t *testing.T) {
	fixedDate := time.Date(2009, 11, 17, 20, 34, 58, 651387237, time.UTC)

	tests := []struct {
		name        string
		rawRedirect string
		timestamp   time.Time
		want        string
	}{
		{"pomerium", "https://pomerium.io/.pomerium/callback", fixedDate, "wq3rAjRGN96RXS8TAzH-uxQTD0XgY_8ZYEKMiOLD5P4="},
		{"google", "https://google.com/.pomerium/callback", fixedDate, "7EYHZObq167CuyuPm5CqOtkU4zg5dFeUCs7W7QOrgNQ="},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &Proxy{}
			if got := p.signRedirectURL(tt.rawRedirect, tt.timestamp); got != tt.want {
				t.Errorf("Proxy.signRedirectURL() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestProxy_GetSignOutURL(t *testing.T) {

	tests := []struct {
		name         string
		authenticate string
		redirect     string
		wantPrefix   string
	}{
		{"without scheme", "auth.corp.pomerium.io", "hello.corp.pomerium.io", "https://auth.corp.pomerium.io/sign_out?redirect_uri=https%3A%2F%2Fhello.corp.pomerium.io"},
		{"with scheme", "https://auth.corp.pomerium.io", "https://hello.corp.pomerium.io", "https://auth.corp.pomerium.io/sign_out?redirect_uri=https%3A%2F%2Fhello.corp.pomerium.io"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			authenticateURL, _ := urlParse(tt.authenticate)
			redirectURL, _ := urlParse(tt.redirect)

			p := &Proxy{}
			// signature is ignored as it is tested above. Avoids testing time.Now
			if got := p.GetSignOutURL(authenticateURL, redirectURL); !strings.HasPrefix(got.String(), tt.wantPrefix) {
				t.Errorf("Proxy.GetSignOutURL() = %v, wantPrefix %v", got.String(), tt.wantPrefix)
			}
		})
	}
}

func TestProxy_GetSignInURL(t *testing.T) {

	tests := []struct {
		name         string
		authenticate string
		redirect     string
		state        string

		wantPrefix string
	}{
		{"without scheme", "auth.corp.pomerium.io", "hello.corp.pomerium.io", "example_state", "https://auth.corp.pomerium.io/sign_in?redirect_uri=https%3A%2F%2Fhello.corp.pomerium.io&response_type=code&shared_secret=shared-secret"},
		{"with scheme", "https://auth.corp.pomerium.io", "https://hello.corp.pomerium.io", "example_state", "https://auth.corp.pomerium.io/sign_in?redirect_uri=https%3A%2F%2Fhello.corp.pomerium.io&response_type=code&shared_secret=shared-secret"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &Proxy{SharedKey: "shared-secret"}
			authenticateURL, _ := urlParse(tt.authenticate)
			redirectURL, _ := urlParse(tt.redirect)

			if got := p.GetSignInURL(authenticateURL, redirectURL, tt.state); !strings.HasPrefix(got.String(), tt.wantPrefix) {
				t.Errorf("Proxy.GetSignOutURL() = %v, wantPrefix %v", got.String(), tt.wantPrefix)
			}

		})
	}
}

func TestProxy_Favicon(t *testing.T) {
	proxy, err := New(testOptions())
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest("GET", "/favicon.ico", nil)

	rr := httptest.NewRecorder()
	proxy.Favicon(rr, req)
	if status := rr.Code; status != http.StatusNotFound {
		t.Errorf("handler returned wrong status code: got %v want %v", status, http.StatusNotFound)
	}
	// todo(bdd) : good way of mocking auth then serving a simple favicon?
}

func TestProxy_Signout(t *testing.T) {
	proxy, err := New(testOptions())
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest("GET", "/.pomerium/sign_out", nil)

	rr := httptest.NewRecorder()
	proxy.SignOut(rr, req)
	if status := rr.Code; status != http.StatusFound {
		t.Errorf("handler returned wrong status code: got %v want %v", status, http.StatusFound)
	}
	// todo(bdd) : good way of mocking auth then serving a simple favicon?
}

func TestProxy_OAuthStart(t *testing.T) {
	proxy, err := New(testOptions())
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest("GET", "/oauth-start", nil)

	rr := httptest.NewRecorder()
	proxy.OAuthStart(rr, req)
	// expect oauth redirect
	if status := rr.Code; status != http.StatusFound {
		t.Errorf("handler returned wrong status code: got %v want %v", status, http.StatusFound)
	}
	// expected url
	expected := `<a href="https://sso-auth.corp.beyondperimeter.com/sign_in`
	body := rr.Body.String()
	if !strings.HasPrefix(body, expected) {
		t.Errorf("handler returned unexpected body: got %v want %v", body, expected)
	}
}
func TestProxy_Handler(t *testing.T) {
	proxy, err := New(testOptions())
	if err != nil {
		t.Fatal(err)
	}
	h := proxy.Handler()
	if h == nil {
		t.Error("handler cannot be nil")
	}
	mux := http.NewServeMux()
	mux.Handle("/", h)
	req := httptest.NewRequest("GET", "/ping", nil)

	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	expected := version.UserAgent()
	body := rr.Body.String()
	if body != expected {
		t.Errorf("handler returned unexpected body: got %v want %v", body, expected)
	}
}

// func (p *Proxy) OAuthCallback(w http.ResponseWriter, r *http.Request) {
// 	err := r.ParseForm()
// 	if err != nil {
// 		log.FromRequest(r).Error().Err(err).Msg("failed parsing request form")
// 		httputil.ErrorResponse(w, r, err.Error(), http.StatusInternalServerError)
// 		return
// 	}
// 	errorString := r.Form.Get("error")
// 	if errorString != "" {
// 		httputil.ErrorResponse(w, r, errorString, http.StatusForbidden)
// 		return
// 	}
// 	// We begin the process of redeeming the code for an access token.
// 	session, err := p.AuthenticateRedeem(r.Form.Get("code"))
// 	if err != nil {
// 		log.FromRequest(r).Error().Err(err).Msg("error redeeming authorization code")
// 		httputil.ErrorResponse(w, r, "Internal error", http.StatusInternalServerError)
// 		return
// 	}

// 	encryptedState := r.Form.Get("state")
// 	stateParameter := &StateParameter{}
// 	err = p.cipher.Unmarshal(encryptedState, stateParameter)
// 	if err != nil {
// 		log.FromRequest(r).Error().Err(err).Msg("could not unmarshal state")
// 		httputil.ErrorResponse(w, r, "Internal error", http.StatusInternalServerError)
// 		return
// 	}

// 	c, err := p.csrfStore.GetCSRF(r)
// 	if err != nil {
// 		log.FromRequest(r).Error().Err(err).Msg("failed parsing csrf cookie")
// 		httputil.ErrorResponse(w, r, err.Error(), http.StatusBadRequest)
// 		return
// 	}
// 	p.csrfStore.ClearCSRF(w, r)

// 	encryptedCSRF := c.Value
// 	csrfParameter := &StateParameter{}
// 	err = p.cipher.Unmarshal(encryptedCSRF, csrfParameter)
// 	if err != nil {
// 		log.FromRequest(r).Error().Err(err).Msg("couldn't unmarshal CSRF")
// 		httputil.ErrorResponse(w, r, "Internal error", http.StatusInternalServerError)
// 		return
// 	}

// 	if encryptedState == encryptedCSRF {
// 		log.FromRequest(r).Error().Msg("encrypted state and CSRF should not be equal")
// 		httputil.ErrorResponse(w, r, "Bad request", http.StatusBadRequest)
// 		return
// 	}

// 	if !reflect.DeepEqual(stateParameter, csrfParameter) {
// 		log.FromRequest(r).Error().Msg("state and CSRF should be equal")
// 		httputil.ErrorResponse(w, r, "Bad request", http.StatusBadRequest)
// 		return
// 	}

// 	// We store the session in a cookie and redirect the user back to the application
// 	err = p.sessionStore.SaveSession(w, r, session)
// 	if err != nil {
// 		log.FromRequest(r).Error().Msg("error saving session")
// 		httputil.ErrorResponse(w, r, "Error saving session", http.StatusInternalServerError)
// 		return
// 	}

// 	log.FromRequest(r).Info().
// 		Str("code", r.Form.Get("code")).
// 		Str("state", r.Form.Get("state")).
// 		Str("RefreshToken", session.RefreshToken).
// 		Str("session", session.AccessToken).
// 		Str("RedirectURI", stateParameter.RedirectURI).
// 		Msg("session")

// 	// This is the redirect back to the original requested application
// 	http.Redirect(w, r, stateParameter.RedirectURI, http.StatusFound)
// }

// func TestProxy_OAuthCallback2(t *testing.T) {
// 	proxy, err := New(testOptions())
// 	if err != nil {
// 		t.Fatal(err)
// 	}
// 	testError := url.Values{"error": []string{"There was a bad error to handle"}}
// 	req := httptest.NewRequest("GET", "/oauth-callback", strings.NewReader(testError.Encode()))
// 	if err != nil {
// 		t.Fatal(err)
// 	}
// 	rr := httptest.NewRecorder()
// 	proxy.OAuthCallback)
// 	// expect oauth redirect
// 	if status := rr.Code; status != http.StatusInternalServerError {
// 		t.Errorf("handler returned wrong status code: got %v want %v", status, http.StatusInternalServerError)
// 	}
// 	// expected url
// 	// expected := `<a href="https://sso-auth.corp.beyondperimeter.com/sign_in`
// 	// body := rr.Body.String()
// 	// if !strings.HasPrefix(body, expected) {
// 	// 	t.Errorf("handler returned unexpected body: got %v want %v", body, expected)
// 	// }
// }

func TestProxy_OAuthCallback(t *testing.T) {
	proxy, err := New(testOptions())
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name     string
		method   string
		params   map[string]string
		wantCode int
	}{
		{"nil", http.MethodPost, nil, http.StatusInternalServerError},
		{"error", http.MethodPost, map[string]string{"error": "some error"}, http.StatusForbidden},
		{"state", http.MethodPost, map[string]string{"code": "code"}, http.StatusInternalServerError},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			req := httptest.NewRequest(tt.method, "/.pomerium/callback", nil)
			q := req.URL.Query()
			for k, v := range tt.params {
				q.Add(k, v)
			}
			req.URL.RawQuery = q.Encode()
			fmt.Println("OK OK OK OK")

			fmt.Println(req.URL.String())
			w := httptest.NewRecorder()
			proxy.OAuthCallback(w, req)
			if status := w.Code; status != tt.wantCode {
				t.Errorf("handler returned wrong status code: got %v want %v", status, tt.wantCode)
			}
		})
	}
}
