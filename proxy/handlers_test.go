package proxy

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/pomerium/pomerium/internal/sessions"
	"github.com/pomerium/pomerium/internal/version"
	"github.com/pomerium/pomerium/proxy/clients"
)

type mockCipher struct{}

func (a mockCipher) Encrypt(s []byte) ([]byte, error) {
	if string(s) == "error" {
		return []byte(""), errors.New("error encrypting")
	}
	return []byte("OK"), nil
}

func (a mockCipher) Decrypt(s []byte) ([]byte, error) {
	if string(s) == "error" {
		return []byte(""), errors.New("error encrypting")
	}
	return []byte("OK"), nil
}
func (a mockCipher) Marshal(s interface{}) (string, error) { return "ok", nil }
func (a mockCipher) Unmarshal(s string, i interface{}) error {
	if string(s) == "unmarshal error" || string(s) == "error" {
		return errors.New("error")
	}
	return nil
}

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
	expected := `<a href="https://authenticate.corp.beyondperimeter.com/sign_in`
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

func TestProxy_OAuthCallback(t *testing.T) {
	normalSession := sessions.MockSessionStore{
		Session: &sessions.SessionState{
			AccessToken:      "AccessToken",
			RefreshToken:     "RefreshToken",
			LifetimeDeadline: time.Now().Add(10 * time.Second),
			RefreshDeadline:  time.Now().Add(-10 * time.Second),
		},
	}
	normalAuth := clients.MockAuthenticate{
		RedeemResponse: &sessions.SessionState{
			AccessToken:      "AccessToken",
			RefreshToken:     "RefreshToken",
			LifetimeDeadline: time.Now().Add(10 * time.Second),
		},
	}
	normalCsrf := sessions.MockCSRFStore{
		ResponseCSRF: "ok",
		GetError:     nil,
		Cookie: &http.Cookie{
			Name:  "something_csrf",
			Value: "csrf_state",
		}}
	tests := []struct {
		name          string
		csrf          sessions.MockCSRFStore
		session       sessions.MockSessionStore
		authenticator clients.MockAuthenticate
		params        map[string]string
		wantCode      int
	}{
		{"good", normalCsrf, normalSession, normalAuth, map[string]string{"code": "code", "state": "state"}, http.StatusFound},
		{"error", normalCsrf, normalSession, normalAuth, map[string]string{"error": "some error"}, http.StatusForbidden},
		{"code err", normalCsrf, normalSession, clients.MockAuthenticate{RedeemError: errors.New("error")}, map[string]string{"code": "error"}, http.StatusInternalServerError},
		{"state err", normalCsrf, normalSession, normalAuth, map[string]string{"code": "code", "state": "error"}, http.StatusInternalServerError},
		{"csrf err", sessions.MockCSRFStore{GetError: errors.New("error")}, normalSession, normalAuth, map[string]string{"code": "code", "state": "state"}, http.StatusBadRequest},
		{"unmarshal err", sessions.MockCSRFStore{
			Cookie: &http.Cookie{
				Name:  "something_csrf",
				Value: "unmarshal error",
			},
		}, normalSession, normalAuth, map[string]string{"code": "code", "state": "state"}, http.StatusInternalServerError},
		{"encrypted state != CSRF", normalCsrf, normalSession, normalAuth, map[string]string{"code": "code", "state": "csrf_state"}, http.StatusBadRequest},
		{"session save err", normalCsrf, sessions.MockSessionStore{SaveError: errors.New("error")}, normalAuth, map[string]string{"code": "code", "state": "state"}, http.StatusInternalServerError},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			proxy, err := New(testOptions())
			if err != nil {
				t.Fatal(err)
			}
			proxy.sessionStore = &tt.session
			proxy.csrfStore = tt.csrf
			proxy.AuthenticateClient = tt.authenticator
			proxy.cipher = mockCipher{}
			// proxy.Csrf
			req := httptest.NewRequest(http.MethodPost, "/.pomerium/callback", nil)
			q := req.URL.Query()
			for k, v := range tt.params {
				q.Add(k, v)
			}
			req.URL.RawQuery = q.Encode()
			w := httptest.NewRecorder()
			proxy.OAuthCallback(w, req)
			if status := w.Code; status != tt.wantCode {
				t.Errorf("handler returned wrong status code: got %v want %v", status, tt.wantCode)
			}
		})
	}

}
func Test_extendDeadline(t *testing.T) {
	tests := []struct {
		name string
		ttl  time.Duration
		want time.Time
	}{
		{"good", time.Second, time.Now().Add(time.Second).Truncate(time.Second)},
		{"test nanoseconds truncated", 500 * time.Nanosecond, time.Now().Truncate(time.Second)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := extendDeadline(tt.ttl); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("extendDeadline() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestProxy_router(t *testing.T) {
	configBlob := `[{"from":"corp.example.com","to":"example.com"}]` //valid yaml
	policy := base64.URLEncoding.EncodeToString([]byte(configBlob))
	tests := []struct {
		name   string
		host   string
		mux    string
		route  http.Handler
		wantOk bool
	}{
		{"good corp", "https://corp.example.com", policy, nil, true},
		{"good with slash", "https://corp.example.com/", policy, nil, true},
		{"good with path", "https://corp.example.com/123", policy, nil, true},
		// {"multiple", "https://corp.example.com/", map[string]string{"corp.unrelated.com": "unrelated.com", "corp.example.com": "example.com"}, nil, true},
		{"bad corp", "https://notcorp.example.com/123", policy, nil, false},
		{"bad sub-sub", "https://notcorp.corp.example.com/123", policy, nil, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opts := testOptions()
			opts.Policy = tt.mux
			p, err := New(opts)
			if err != nil {
				t.Fatal(err)
			}
			p.AuthenticateClient = clients.MockAuthenticate{}
			p.cipher = mockCipher{}

			req := httptest.NewRequest("GET", tt.host, nil)
			_, ok := p.router(req)
			if ok != tt.wantOk {
				t.Errorf("Proxy.router() ok = %v, want %v", ok, tt.wantOk)
			}
		})
	}
}

func TestProxy_Proxy(t *testing.T) {
	goodSession := &sessions.SessionState{
		AccessToken:      "AccessToken",
		RefreshToken:     "RefreshToken",
		LifetimeDeadline: time.Now().Add(10 * time.Second),
		RefreshDeadline:  time.Now().Add(10 * time.Second),
	}

	tests := []struct {
		name          string
		host          string
		session       sessions.SessionStore
		authenticator clients.Authenticator
		authorizer    clients.Authorizer
		wantStatus    int
	}{
		// weirdly, we want 503 here because that means proxy is trying to route a domain (example.com) that we dont control. Weird. I know.
		{"good", "https://corp.example.com/test", &sessions.MockSessionStore{Session: goodSession}, clients.MockAuthenticate{}, clients.MockAuthorize{AuthorizeResponse: true}, http.StatusServiceUnavailable},
		{"unexpected error", "https://corp.example.com/test", &sessions.MockSessionStore{LoadError: errors.New("ok")}, clients.MockAuthenticate{}, clients.MockAuthorize{AuthorizeResponse: true}, http.StatusInternalServerError},
		// redirect to start auth process
		{"unknown host", "https://notcorp.example.com/test", &sessions.MockSessionStore{Session: goodSession}, clients.MockAuthenticate{}, clients.MockAuthorize{AuthorizeResponse: true}, http.StatusNotFound},
		{"user forbidden", "https://notcorp.example.com/test", &sessions.MockSessionStore{Session: goodSession}, clients.MockAuthenticate{}, clients.MockAuthorize{AuthorizeResponse: false}, http.StatusForbidden},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opts := testOptions()
			p, err := New(opts)
			if err != nil {
				t.Fatal(err)
			}
			p.cipher = mockCipher{}
			p.sessionStore = tt.session
			p.AuthenticateClient = tt.authenticator
			p.AuthorizeClient = tt.authorizer

			r := httptest.NewRequest("GET", tt.host, nil)
			w := httptest.NewRecorder()
			p.Proxy(w, r)
			if status := w.Code; status != tt.wantStatus {
				t.Errorf("handler returned wrong status code: got %v want %v \n body %s", status, tt.wantStatus, w.Body.String())
			}

		})
	}
}

func TestProxy_Authenticate(t *testing.T) {
	configBlob := `[{"from":"corp.example.com","to":"example.com"}]` //valid yaml
	policy := base64.URLEncoding.EncodeToString([]byte(configBlob))

	goodSession := &sessions.SessionState{
		User:             "user",
		Email:            "email@email.com",
		Groups:           []string{"group1"},
		AccessToken:      "AccessToken",
		RefreshToken:     "RefreshToken",
		LifetimeDeadline: time.Now().Add(10 * time.Second),
		RefreshDeadline:  time.Now().Add(10 * time.Second),
	}
	testAuth := clients.MockAuthenticate{
		RedeemResponse: goodSession,
	}

	tests := []struct {
		name          string
		host          string
		mux           string
		session       sessions.SessionStore
		authenticator clients.Authenticator
		wantErr       bool
	}{
		{"cannot save session",
			"https://corp.example.com/",
			policy,
			&sessions.MockSessionStore{Session: &sessions.SessionState{
				User:             "user",
				Email:            "email@email.com",
				Groups:           []string{"group1"},
				AccessToken:      "AccessToken",
				RefreshToken:     "RefreshToken",
				LifetimeDeadline: time.Now().Add(10 * time.Second),
				RefreshDeadline:  time.Now().Add(10 * time.Second),
			}, SaveError: errors.New("error")},
			testAuth, true},

		{"cannot load session",
			"https://corp.example.com/",
			policy,
			&sessions.MockSessionStore{LoadError: errors.New("error")}, testAuth, true},
		{"expired session",
			"https://corp.example.com/",
			policy,
			&sessions.MockSessionStore{
				Session: &sessions.SessionState{
					User:             "user",
					Email:            "email@email.com",
					Groups:           []string{"group1"},
					AccessToken:      "AccessToken",
					RefreshToken:     "RefreshToken",
					LifetimeDeadline: time.Now().Add(10 * time.Second),
					RefreshDeadline:  time.Now().Add(-10 * time.Second),
				}},
			clients.MockAuthenticate{
				RefreshError: errors.New("error"),
				RefreshResponse: &sessions.SessionState{
					User:             "user",
					Email:            "email@email.com",
					Groups:           []string{"group1"},
					AccessToken:      "AccessToken",
					RefreshToken:     "RefreshToken",
					LifetimeDeadline: time.Now().Add(10 * time.Second),
					RefreshDeadline:  time.Now().Add(-10 * time.Second),
				}}, true},
		{"bad refresh authenticator",
			"https://corp.example.com/",
			policy,
			&sessions.MockSessionStore{
				Session: &sessions.SessionState{
					User:             "user",
					Email:            "email@email.com",
					Groups:           []string{"group1"},
					AccessToken:      "AccessToken",
					RefreshToken:     "RefreshToken",
					LifetimeDeadline: time.Now().Add(10 * time.Second),
					RefreshDeadline:  time.Now().Add(-10 * time.Second),
				},
			},
			clients.MockAuthenticate{
				RefreshError: errors.New("error"),
				RefreshResponse: &sessions.SessionState{
					User:             "user",
					Email:            "email@email.com",
					Groups:           []string{"group1"},
					AccessToken:      "AccessToken",
					RefreshToken:     "RefreshToken",
					LifetimeDeadline: time.Now().Add(10 * time.Second),
					RefreshDeadline:  time.Now().Add(-10 * time.Second),
				}},
			true},

		{"good",
			"https://corp.example.com/",
			policy,
			&sessions.MockSessionStore{Session: &sessions.SessionState{
				User:             "user",
				Email:            "email@email.com",
				Groups:           []string{"group1"},
				AccessToken:      "AccessToken",
				RefreshToken:     "RefreshToken",
				LifetimeDeadline: time.Now().Add(10 * time.Second),
				RefreshDeadline:  time.Now().Add(10 * time.Second),
			}}, testAuth, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opts := testOptions()
			opts.Policy = tt.mux
			p, err := New(opts)
			if err != nil {
				t.Fatal(err)
			}
			p.sessionStore = tt.session
			p.AuthenticateClient = tt.authenticator
			p.cipher = mockCipher{}
			r := httptest.NewRequest("GET", tt.host, nil)
			w := httptest.NewRecorder()
			fmt.Printf("%s", tt.name)

			if err := p.Authenticate(w, r); (err != nil) != tt.wantErr {
				t.Errorf("Proxy.Authenticate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
