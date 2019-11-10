package proxy

import (
	"bytes"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/encoding"
	"github.com/pomerium/pomerium/internal/encoding/mock"
	"github.com/pomerium/pomerium/internal/httputil"
	"github.com/pomerium/pomerium/internal/sessions"
	"github.com/pomerium/pomerium/proxy/clients"

	"github.com/google/go-cmp/cmp"
	"gopkg.in/square/go-jose.v2/jwt"
)

func TestProxy_RobotsTxt(t *testing.T) {
	proxy := Proxy{}
	req := httptest.NewRequest(http.MethodGet, "/robots.txt", nil)
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

func TestProxy_Signout(t *testing.T) {
	opts := testOptions(t)
	err := ValidateOptions(opts)
	if err != nil {
		t.Fatal(err)
	}
	proxy, err := New(opts)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "/.pomerium/sign_out", nil)
	rr := httptest.NewRecorder()
	proxy.SignOut(rr, req)
	if status := rr.Code; status != http.StatusFound {
		t.Errorf("handler returned wrong status code: got %v want %v", status, http.StatusFound)
	}
	body := rr.Body.String()
	want := (proxy.authenticateURL.String())
	if !strings.Contains(body, want) {
		t.Errorf("handler returned unexpected body: got %v want %s ", body, want)
	}
}

func TestProxy_UserDashboard(t *testing.T) {
	opts := testOptions(t)
	tests := []struct {
		name       string
		ctxError   error
		options    config.Options
		method     string
		cipher     encoding.MarshalUnmarshaler
		session    sessions.SessionStore
		authorizer clients.Authorizer

		wantAdminForm bool
		wantStatus    int
	}{
		{"good", nil, opts, http.MethodGet, &mock.Encoder{}, &sessions.MockSessionStore{Session: &sessions.State{Email: "user@test.example", Expiry: jwt.NewNumericDate(time.Now().Add(10 * time.Minute))}}, clients.MockAuthorize{}, false, http.StatusOK},
		{"session context error", errors.New("error"), opts, http.MethodGet, &mock.Encoder{}, &sessions.MockSessionStore{Session: &sessions.State{Email: "user@test.example", Expiry: jwt.NewNumericDate(time.Now().Add(10 * time.Minute))}}, clients.MockAuthorize{}, false, http.StatusInternalServerError},
		{"want admin form good admin authorization", nil, opts, http.MethodGet, &mock.Encoder{}, &sessions.MockSessionStore{Session: &sessions.State{Email: "user@test.example", Expiry: jwt.NewNumericDate(time.Now().Add(10 * time.Minute))}}, clients.MockAuthorize{IsAdminResponse: true}, true, http.StatusOK},
		{"is admin but authorization fails", nil, opts, http.MethodGet, &mock.Encoder{}, &sessions.MockSessionStore{Session: &sessions.State{Email: "user@test.example", Expiry: jwt.NewNumericDate(time.Now().Add(10 * time.Minute))}}, clients.MockAuthorize{IsAdminError: errors.New("err")}, false, http.StatusInternalServerError},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p, err := New(tt.options)
			if err != nil {
				t.Fatal(err)
			}
			p.encoder = tt.cipher
			p.sessionStore = tt.session
			p.AuthorizeClient = tt.authorizer

			r := httptest.NewRequest(tt.method, "/", nil)
			state, _ := tt.session.LoadSession(r)
			ctx := r.Context()
			ctx = sessions.NewContext(ctx, state, tt.ctxError)
			r = r.WithContext(ctx)

			r.Header.Set("Accept", "application/json")

			w := httptest.NewRecorder()
			p.UserDashboard(w, r)
			if status := w.Code; status != tt.wantStatus {
				t.Errorf("status code: got %v want %v", status, tt.wantStatus)
				t.Errorf("\n%+v", opts)
				t.Errorf("\n%+v", w.Body.String())

			}
			if adminForm := strings.Contains(w.Body.String(), "impersonate"); adminForm != tt.wantAdminForm {
				t.Errorf("wanted admin form  got %v want %v", adminForm, tt.wantAdminForm)
				t.Errorf("\n%+v", w.Body.String())
			}
		})
	}
}

func TestProxy_Impersonate(t *testing.T) {
	t.Parallel()
	opts := testOptions(t)
	tests := []struct {
		name         string
		malformed    bool
		options      config.Options
		ctxError     error
		method       string
		email        string
		groups       string
		csrf         string
		cipher       encoding.MarshalUnmarshaler
		sessionStore sessions.SessionStore
		authorizer   clients.Authorizer
		wantStatus   int
	}{
		{"good", false, opts, nil, http.MethodPost, "user@blah.com", "", "", &mock.Encoder{}, &sessions.MockSessionStore{Session: &sessions.State{Email: "user@test.example"}}, clients.MockAuthorize{IsAdminResponse: true}, http.StatusFound},
		{"good", false, opts, errors.New("error"), http.MethodPost, "user@blah.com", "", "", &mock.Encoder{}, &sessions.MockSessionStore{Session: &sessions.State{Email: "user@test.example"}}, clients.MockAuthorize{IsAdminResponse: true}, http.StatusInternalServerError},
		{"session load error", false, opts, nil, http.MethodPost, "user@blah.com", "", "", &mock.Encoder{}, &sessions.MockSessionStore{LoadError: errors.New("err"), Session: &sessions.State{Email: "user@test.example"}}, clients.MockAuthorize{IsAdminResponse: true}, http.StatusFound},
		{"non admin users rejected", false, opts, nil, http.MethodPost, "user@blah.com", "", "", &mock.Encoder{}, &sessions.MockSessionStore{Session: &sessions.State{Expiry: jwt.NewNumericDate(time.Now().Add(10 * time.Minute)), Email: "user@test.example"}}, clients.MockAuthorize{IsAdminResponse: false}, http.StatusForbidden},
		{"non admin users rejected on error", false, opts, nil, http.MethodPost, "user@blah.com", "", "", &mock.Encoder{}, &sessions.MockSessionStore{Session: &sessions.State{Expiry: jwt.NewNumericDate(time.Now().Add(10 * time.Minute)), Email: "user@test.example"}}, clients.MockAuthorize{IsAdminResponse: true, IsAdminError: errors.New("err")}, http.StatusForbidden},
		{"groups", false, opts, nil, http.MethodPost, "user@blah.com", "group1,group2", "", &mock.Encoder{}, &sessions.MockSessionStore{Session: &sessions.State{Expiry: jwt.NewNumericDate(time.Now().Add(10 * time.Minute)), Email: "user@test.example"}}, clients.MockAuthorize{IsAdminResponse: true}, http.StatusFound},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p, err := New(tt.options)
			if err != nil {
				t.Fatal(err)
			}
			p.encoder = tt.cipher
			p.sessionStore = tt.sessionStore
			p.AuthorizeClient = tt.authorizer
			postForm := url.Values{}
			postForm.Add("email", tt.email)
			postForm.Add("group", tt.groups)
			postForm.Set("csrf", tt.csrf)
			uri := &url.URL{Path: "/"}

			r := httptest.NewRequest(tt.method, uri.String(), bytes.NewBufferString(postForm.Encode()))
			state, _ := tt.sessionStore.LoadSession(r)
			ctx := r.Context()
			ctx = sessions.NewContext(ctx, state, tt.ctxError)
			r = r.WithContext(ctx)

			r.Header.Set("Content-Type", "application/x-www-form-urlencoded; param=value")
			w := httptest.NewRecorder()
			p.Impersonate(w, r)
			if status := w.Code; status != tt.wantStatus {
				t.Errorf("status code: got %v want %v", status, tt.wantStatus)
				t.Errorf("\n%+v", opts)
			}
		})
	}
}

func TestProxy_SignOut(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name        string
		verb        string
		redirectURL string
		wantStatus  int
	}{
		{"good post", http.MethodPost, "https://test.example", http.StatusFound},
		{"good get", http.MethodGet, "https://test.example", http.StatusFound},
		{"good empty default", http.MethodGet, "", http.StatusFound},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opts := testOptions(t)
			p, err := New(opts)
			if err != nil {
				t.Fatal(err)
			}
			postForm := url.Values{}
			postForm.Add("redirect_uri", tt.redirectURL)
			uri := &url.URL{Path: "/"}

			query, _ := url.ParseQuery(uri.RawQuery)
			if tt.verb == http.MethodGet {
				query.Add("redirect_uri", tt.redirectURL)
				uri.RawQuery = query.Encode()
			}
			r := httptest.NewRequest(tt.verb, uri.String(), bytes.NewBufferString(postForm.Encode()))
			w := httptest.NewRecorder()
			if tt.verb == http.MethodPost {
				r.Header.Set("Content-Type", "application/x-www-form-urlencoded; param=value")
			}
			p.SignOut(w, r)
			if status := w.Code; status != tt.wantStatus {
				t.Errorf("status code: got %v want %v", status, tt.wantStatus)
			}

		})
	}
}
func uriParseHelper(s string) *url.URL {
	uri, err := url.Parse(s)
	if err != nil {
		panic(err)
	}
	return uri
}
func TestProxy_VerifyWithMiddleware(t *testing.T) {
	t.Parallel()
	opts := testOptions(t)
	tests := []struct {
		name      string
		options   config.Options
		ctxError  error
		method    string
		qp        string
		path      string
		verifyURI string

		cipher       encoding.MarshalUnmarshaler
		sessionStore sessions.SessionStore
		authorizer   clients.Authorizer
		wantStatus   int
		wantBody     string
	}{
		{"good", opts, nil, http.MethodGet, "", "/", "https://some.domain.example", &mock.Encoder{}, &sessions.MockSessionStore{Session: &sessions.State{Email: "user@test.example", Expiry: jwt.NewNumericDate(time.Now().Add(10 * time.Minute))}}, clients.MockAuthorize{AuthorizeResponse: true}, http.StatusOK, ""},
		{"good verify only", opts, nil, http.MethodGet, "", "/verify", "https://some.domain.example", &mock.Encoder{}, &sessions.MockSessionStore{Session: &sessions.State{Email: "user@test.example", Expiry: jwt.NewNumericDate(time.Now().Add(10 * time.Minute))}}, clients.MockAuthorize{AuthorizeResponse: true}, http.StatusOK, ""},
		{"bad naked domain uri", opts, nil, http.MethodGet, "", "/", "a.naked.domain", &mock.Encoder{}, &sessions.MockSessionStore{Session: &sessions.State{Email: "user@test.example", Expiry: jwt.NewNumericDate(time.Now().Add(10 * time.Minute))}}, clients.MockAuthorize{AuthorizeResponse: true}, http.StatusBadRequest, "{\"error\":\"bad verification uri\"}\n"},
		{"bad naked domain uri verify only", opts, nil, http.MethodGet, "", "/verify", "a.naked.domain", &mock.Encoder{}, &sessions.MockSessionStore{Session: &sessions.State{Email: "user@test.example", Expiry: jwt.NewNumericDate(time.Now().Add(10 * time.Minute))}}, clients.MockAuthorize{AuthorizeResponse: true}, http.StatusBadRequest, "{\"error\":\"bad verification uri\"}\n"},
		{"bad empty verification uri", opts, nil, http.MethodGet, "", "/", " ", &mock.Encoder{}, &sessions.MockSessionStore{Session: &sessions.State{Email: "user@test.example", Expiry: jwt.NewNumericDate(time.Now().Add(10 * time.Minute))}}, clients.MockAuthorize{AuthorizeResponse: true}, http.StatusBadRequest, "{\"error\":\"bad verification uri\"}\n"},
		{"bad empty verification uri verify only", opts, nil, http.MethodGet, "", "/verify", " ", &mock.Encoder{}, &sessions.MockSessionStore{Session: &sessions.State{Email: "user@test.example", Expiry: jwt.NewNumericDate(time.Now().Add(10 * time.Minute))}}, clients.MockAuthorize{AuthorizeResponse: true}, http.StatusBadRequest, "{\"error\":\"bad verification uri\"}\n"},
		{"not authorized", opts, nil, http.MethodGet, "", "/", "https://some.domain.example", &mock.Encoder{}, &sessions.MockSessionStore{Session: &sessions.State{Email: "user@test.example", Expiry: jwt.NewNumericDate(time.Now().Add(10 * time.Minute))}}, clients.MockAuthorize{AuthorizeResponse: false}, http.StatusUnauthorized, "{\"error\":\"user@test.example is not authorized for some.domain.example\"}\n"},
		{"not authorized verify endpoint", opts, nil, http.MethodGet, "", "/verify", "https://some.domain.example", &mock.Encoder{}, &sessions.MockSessionStore{Session: &sessions.State{Email: "user@test.example", Expiry: jwt.NewNumericDate(time.Now().Add(10 * time.Minute))}}, clients.MockAuthorize{AuthorizeResponse: false}, http.StatusUnauthorized, "{\"error\":\"user@test.example is not authorized for some.domain.example\"}\n"},
		{"not authorized expired, redirect to auth", opts, sessions.ErrExpired, http.MethodGet, "", "/", "https://some.domain.example", &mock.Encoder{}, &sessions.MockSessionStore{Session: &sessions.State{Email: "user@test.example", Expiry: jwt.NewNumericDate(time.Now().Add(-10 * time.Minute))}}, clients.MockAuthorize{AuthorizeResponse: false}, http.StatusFound, ""},
		{"not authorized expired, don't redirect!", opts, sessions.ErrExpired, http.MethodGet, "", "/verify", "https://some.domain.example", &mock.Encoder{}, &sessions.MockSessionStore{Session: &sessions.State{Email: "user@test.example", Expiry: jwt.NewNumericDate(time.Now().Add(-10 * time.Minute))}}, clients.MockAuthorize{AuthorizeResponse: false}, http.StatusUnauthorized, "{\"error\":\"internal/sessions: validation failed, token is expired (exp)\"}\n"},
		{"not authorized because of error", opts, nil, http.MethodGet, "", "/", "https://some.domain.example", &mock.Encoder{}, &sessions.MockSessionStore{Session: &sessions.State{Email: "user@test.example", Expiry: jwt.NewNumericDate(time.Now().Add(10 * time.Minute))}}, clients.MockAuthorize{AuthorizeError: errors.New("authz error")}, http.StatusInternalServerError, "{\"error\":\"authz error\"}\n"},
		{"not authorized expired, do not redirect to auth", opts, nil, http.MethodGet, "", "/verify", "https://some.domain.example", &mock.Encoder{}, &sessions.MockSessionStore{Session: &sessions.State{Email: "user@test.example", Expiry: jwt.NewNumericDate(time.Now().Add(-10 * time.Minute))}}, clients.MockAuthorize{AuthorizeResponse: false}, http.StatusUnauthorized, "{\"error\":\"internal/sessions: validation failed, token is expired (exp)\"}\n"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p, err := New(tt.options)
			if err != nil {
				t.Fatal(err)
			}
			p.encoder = tt.cipher
			p.sessionStore = tt.sessionStore
			p.AuthorizeClient = tt.authorizer
			p.UpdateOptions(tt.options)
			uri := &url.URL{Path: tt.path}
			queryString := uri.Query()
			queryString.Set("donstrip", "ok")
			if tt.qp != "" {
				queryString.Set(tt.qp, "true")
			}
			if tt.verifyURI != "" {
				queryString.Set("uri", tt.verifyURI)
			}

			uri.RawQuery = queryString.Encode()

			r := httptest.NewRequest(tt.method, uri.String(), nil)
			state, err := tt.sessionStore.LoadSession(r)
			if err != nil {
				t.Fatal(err)
			}
			ctx := r.Context()
			ctx = sessions.NewContext(ctx, state, tt.ctxError)
			r = r.WithContext(ctx)
			r.Header.Set("Authorization", "Bearer blah")
			r.Header.Set("Accept", "application/json")

			w := httptest.NewRecorder()
			router := p.registerFwdAuthHandlers()
			router.ServeHTTP(w, r)
			if status := w.Code; status != tt.wantStatus {
				t.Errorf("status code: got %v want %v", status, tt.wantStatus)
				t.Errorf("\n%+v", w.Body.String())
			}

			if tt.wantBody != "" {
				body := w.Body.String()
				if diff := cmp.Diff(body, tt.wantBody); diff != "" {
					t.Errorf("wrong body\n%s", diff)
				}
			}
		})
	}
}
func TestProxy_Callback(t *testing.T) {
	t.Parallel()
	opts := testOptions(t)
	tests := []struct {
		name    string
		options config.Options

		method string

		scheme string
		host   string
		path   string

		qp map[string]string

		cipher       encoding.MarshalUnmarshaler
		sessionStore sessions.SessionStore
		authorizer   clients.Authorizer
		wantStatus   int
		wantBody     string
	}{
		{"good", opts, http.MethodGet, "http", "example.com", "/", map[string]string{"pomerium_programmatic_destination_url": "ok", "pomerium_jwt": "KBEjQ9rnCxaAX-GOqetGw9ivEQURqts3zZ2mNGy0wnVa3SbtM399KlBq2nZ-9wM21FfsZX52er4jlmC7kPEKM3P7uZ41zR0zeys1-_74a5tQp-vsf1WXZfRsgVOuBcWPkMiWEoc379JFHxGDudp5VhU8B-dcQt4f3_PtLTHARkuH54io1Va2gNMq4Hiy8sQ1MPGCQeltH_JMzzdDpXdmdusWrXUvCGkba24muvAV06D8XRVJj6Iu9eK94qFnqcHc7wzziEbb8ADBues9dwbtb6jl8vMWz5rN6XvXqA5YpZv_MQZlsrO4oXFFQDevdgB84cX1tVbVu6qZvK_yQBZqzpOjWA9uIaoSENMytoXuWAlFO_sXjswfX8JTNdGwzB7qQRNPqxVG_sM_tzY3QhPm8zqwEzsXG5DokxZfVt2I5WJRUEovFDb4BnK9KFnnkEzLEdMudixVnXeGmTtycgJvoTeTCQRPfDYkcgJ7oKf4tGea-W7z5UAVa2RduJM9ZoM6YtJX7jgDm__PvvqcE0knJUF87XHBzdcOjoDF-CUze9xDJgNBlvPbJqVshKrwoqSYpePSDH9GUCNKxGequW3Ma8GvlFfhwd0rK6IZG-XWkyk0XSWQIGkDSjAvhB1wsOusCCguDjbpVZpaW5MMyTkmx68pl6qlIKT5UCcrVPl4ix5ZEj91mUDF0O1t04haD7VZuLVFXVGmqtFrBKI76sdYN-zkokaa1_chPRTyqMQFlqu_8LD6-RiK3UccGM-dEmnX72i91NP9F9OK0WJr9Cheup1C_P0mjqAO4Cb8oIHm0Oxz_mRqv5QbTGJtb3xwPLPuVjVCiE4gGBcuU2ixpSVf5HUF7y1KicVMCKiX9ATCBtg8sTdQZQnPEtHcHHAvdsnDVwev1LGfqA-Gdvg="}, &mock.Encoder{MarshalResponse: []byte("x")}, &sessions.MockSessionStore{Session: &sessions.State{Email: "user@test.example", Expiry: jwt.NewNumericDate(time.Now().Add(10 * time.Minute))}}, clients.MockAuthorize{AuthorizeResponse: true}, http.StatusFound, ""},
		{"bad decrypt", opts, http.MethodGet, "http", "example.com", "/", map[string]string{"pomerium_jwt": "KBEjQ9rnCxaAX-GOqexGw9ivEQURqts3zZ2mNGy0wnVa3SbtM399KlBq2nZ-9wM21FfsZX52er4jlmC7kPEKM3P7uZ41zR0zeys1-_74a5tQp-vsf1WXZfRsgVOuBcWPkMiWEoc379JFHxGDudp5VhU8B-dcQt4f3_PtLTHARkuH54io1Va2gNMq4Hiy8sQ1MPGCQeltH_JMzzdDpXdmdusWrXUvCGkba24muvAV06D8XRVJj6Iu9eK94qFnqcHc7wzziEbb8ADBues9dwbtb6jl8vMWz5rN6XvXqA5YpZv_MQZlsrO4oXFFQDevdgB84cX1tVbVu6qZvK_yQBZqzpOjWA9uIaoSENMytoXuWAlFO_sXjswfX8JTNdGwzB7qQRNPqxVG_sM_tzY3QhPm8zqwEzsXG5DokxZfVt2I5WJRUEovFDb4BnK9KFnnkEzLEdMudixVnXeGmTtycgJvoTeTCQRPfDYkcgJ7oKf4tGea-W7z5UAVa2RduJM9ZoM6YtJX7jgDm__PvvqcE0knJUF87XHBzdcOjoDF-CUze9xDJgNBlvPbJqVshKrwoqSYpePSDH9GUCNKxGequW3Ma8GvlFfhwd0rK6IZG-XWkyk0XSWQIGkDSjAvhB1wsOusCCguDjbpVZpaW5MMyTkmx68pl6qlIKT5UCcrVPl4ix5ZEj91mUDF0O1t04haD7VZuLVFXVGmqtFrBKI76sdYN-zkokaa1_chPRTyqMQFlqu_8LD6-RiK3UccGM-dEmnX72i91NP9F9OK0WJr9Cheup1C_P0mjqAO4Cb8oIHm0Oxz_mRqv5QbTGJtb3xwPLPuVjVCiE4gGBcuU2ixpSVf5HUF7y1KicVMCKiX9ATCBtg8sTdQZQnPEtHcHHAvdsnDVwev1LGfqA-Gdvg="}, &mock.Encoder{MarshalResponse: []byte("x")}, &sessions.MockSessionStore{Session: &sessions.State{Email: "user@test.example", Expiry: jwt.NewNumericDate(time.Now().Add(10 * time.Minute))}}, clients.MockAuthorize{AuthorizeResponse: true}, http.StatusBadRequest, ""},
		{"bad save session", opts, http.MethodGet, "http", "example.com", "/", map[string]string{"pomerium_jwt": "KBEjQ9rnCxaAX-GOqetGw9ivEQURqts3zZ2mNGy0wnVa3SbtM399KlBq2nZ-9wM21FfsZX52er4jlmC7kPEKM3P7uZ41zR0zeys1-_74a5tQp-vsf1WXZfRsgVOuBcWPkMiWEoc379JFHxGDudp5VhU8B-dcQt4f3_PtLTHARkuH54io1Va2gNMq4Hiy8sQ1MPGCQeltH_JMzzdDpXdmdusWrXUvCGkba24muvAV06D8XRVJj6Iu9eK94qFnqcHc7wzziEbb8ADBues9dwbtb6jl8vMWz5rN6XvXqA5YpZv_MQZlsrO4oXFFQDevdgB84cX1tVbVu6qZvK_yQBZqzpOjWA9uIaoSENMytoXuWAlFO_sXjswfX8JTNdGwzB7qQRNPqxVG_sM_tzY3QhPm8zqwEzsXG5DokxZfVt2I5WJRUEovFDb4BnK9KFnnkEzLEdMudixVnXeGmTtycgJvoTeTCQRPfDYkcgJ7oKf4tGea-W7z5UAVa2RduJM9ZoM6YtJX7jgDm__PvvqcE0knJUF87XHBzdcOjoDF-CUze9xDJgNBlvPbJqVshKrwoqSYpePSDH9GUCNKxGequW3Ma8GvlFfhwd0rK6IZG-XWkyk0XSWQIGkDSjAvhB1wsOusCCguDjbpVZpaW5MMyTkmx68pl6qlIKT5UCcrVPl4ix5ZEj91mUDF0O1t04haD7VZuLVFXVGmqtFrBKI76sdYN-zkokaa1_chPRTyqMQFlqu_8LD6-RiK3UccGM-dEmnX72i91NP9F9OK0WJr9Cheup1C_P0mjqAO4Cb8oIHm0Oxz_mRqv5QbTGJtb3xwPLPuVjVCiE4gGBcuU2ixpSVf5HUF7y1KicVMCKiX9ATCBtg8sTdQZQnPEtHcHHAvdsnDVwev1LGfqA-Gdvg="}, &mock.Encoder{MarshalResponse: []byte("x")}, &sessions.MockSessionStore{SaveError: errors.New("hi")}, clients.MockAuthorize{AuthorizeResponse: true}, http.StatusInternalServerError, ""},
		{"bad base64", opts, http.MethodGet, "http", "example.com", "/", map[string]string{"pomerium_jwt": "^"}, &mock.Encoder{MarshalResponse: []byte("x")}, &sessions.MockSessionStore{Session: &sessions.State{Email: "user@test.example", Expiry: jwt.NewNumericDate(time.Now().Add(10 * time.Minute))}}, clients.MockAuthorize{AuthorizeResponse: true}, http.StatusBadRequest, ""},
		{"malformed redirect", opts, http.MethodGet, "http", "example.com", "/", nil, &mock.Encoder{}, &sessions.MockSessionStore{Session: &sessions.State{Email: "user@test.example", Expiry: jwt.NewNumericDate(time.Now().Add(10 * time.Minute))}}, clients.MockAuthorize{AuthorizeResponse: true}, http.StatusBadRequest, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p, err := New(tt.options)
			if err != nil {
				t.Fatal(err)
			}
			p.encoder = tt.cipher
			p.sessionStore = tt.sessionStore
			p.AuthorizeClient = tt.authorizer
			p.UpdateOptions(tt.options)
			redirectURI := &url.URL{Scheme: tt.scheme, Host: tt.host, Path: tt.path}
			queryString := redirectURI.Query()
			for k, v := range tt.qp {
				queryString.Set(k, v)
			}
			redirectURI.RawQuery = queryString.Encode()

			uri := &url.URL{Path: "/"}
			if tt.qp != nil {
				qu := uri.Query()
				qu.Set("redirect_uri", redirectURI.String())
				uri.RawQuery = qu.Encode()
			}

			r := httptest.NewRequest(tt.method, uri.String(), nil)

			r.Header.Set("Accept", "application/json")

			w := httptest.NewRecorder()
			p.Callback(w, r)
			if status := w.Code; status != tt.wantStatus {
				t.Errorf("status code: got %v want %v", status, tt.wantStatus)
				t.Errorf("\n%+v", w.Body.String())
			}

			if tt.wantBody != "" {
				body := w.Body.String()
				if diff := cmp.Diff(body, tt.wantBody); diff != "" {
					t.Errorf("wrong body\n%s", diff)
				}
			}
		})
	}
}

func TestProxy_ProgrammaticLogin(t *testing.T) {
	t.Parallel()
	opts := testOptions(t)
	tests := []struct {
		name    string
		options config.Options

		method string

		scheme string
		host   string
		path   string
		qp     map[string]string

		wantStatus int
		wantBody   string
	}{
		{"good body not checked", opts, http.MethodGet, "https", "corp.example.example", "/.pomerium/api/v1/login", map[string]string{"redirect_uri": "http://localhost"}, http.StatusOK, ""},
		{"router miss, bad redirect_uri query", opts, http.MethodGet, "https", "corp.example.example", "/.pomerium/api/v1/login", map[string]string{"bad_redirect_uri": "http://localhost"}, http.StatusNotFound, ""},
		{"bad redirect_uri missing scheme", opts, http.MethodGet, "https", "corp.example.example", "/.pomerium/api/v1/login", map[string]string{"redirect_uri": "localhost"}, http.StatusBadRequest, "{\"error\":\"malformed redirect_uri\"}\n"},
		{"bad http method", opts, http.MethodPost, "https", "corp.example.example", "/.pomerium/api/v1/login", map[string]string{"redirect_uri": "http://localhost"}, http.StatusMethodNotAllowed, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p, err := New(tt.options)
			if err != nil {
				t.Fatal(err)
			}
			redirectURI := &url.URL{Scheme: tt.scheme, Host: tt.host, Path: tt.path}
			queryString := redirectURI.Query()
			for k, v := range tt.qp {
				queryString.Set(k, v)
			}
			redirectURI.RawQuery = queryString.Encode()

			r := httptest.NewRequest(tt.method, redirectURI.String(), nil)
			r.Header.Set("Accept", "application/json")

			w := httptest.NewRecorder()
			router := httputil.NewRouter()
			router = p.registerDashboardHandlers(router)
			router.ServeHTTP(w, r)

			if status := w.Code; status != tt.wantStatus {
				t.Errorf("status code: got %v want %v", status, tt.wantStatus)
				t.Errorf("\n%+v", w.Body.String())
			}

			if tt.wantBody != "" {
				body := w.Body.String()
				if diff := cmp.Diff(body, tt.wantBody); diff != "" {
					t.Errorf("wrong body\n%s", diff)
				}
			}

		})
	}
}
