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
	mstore "github.com/pomerium/pomerium/internal/sessions/mock"
	"github.com/pomerium/pomerium/internal/urlutil"
	"github.com/pomerium/pomerium/pkg/cryptutil"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/assert"
	"gopkg.in/square/go-jose.v2/jwt"
)

const goodEncryptionString = "KBEjQ9rnCxaAX-GOqetGw9ivEQURqts3zZ2mNGy0wnVa3SbtM399KlBq2nZ-9wM21FfsZX52er4jlmC7kPEKM3P7uZ41zR0zeys1-_74a5tQp-vsf1WXZfRsgVOuBcWPkMiWEoc379JFHxGDudp5VhU8B-dcQt4f3_PtLTHARkuH54io1Va2gNMq4Hiy8sQ1MPGCQeltH_JMzzdDpXdmdusWrXUvCGkba24muvAV06D8XRVJj6Iu9eK94qFnqcHc7wzziEbb8ADBues9dwbtb6jl8vMWz5rN6XvXqA5YpZv_MQZlsrO4oXFFQDevdgB84cX1tVbVu6qZvK_yQBZqzpOjWA9uIaoSENMytoXuWAlFO_sXjswfX8JTNdGwzB7qQRNPqxVG_sM_tzY3QhPm8zqwEzsXG5DokxZfVt2I5WJRUEovFDb4BnK9KFnnkEzLEdMudixVnXeGmTtycgJvoTeTCQRPfDYkcgJ7oKf4tGea-W7z5UAVa2RduJM9ZoM6YtJX7jgDm__PvvqcE0knJUF87XHBzdcOjoDF-CUze9xDJgNBlvPbJqVshKrwoqSYpePSDH9GUCNKxGequW3Ma8GvlFfhwd0rK6IZG-XWkyk0XSWQIGkDSjAvhB1wsOusCCguDjbpVZpaW5MMyTkmx68pl6qlIKT5UCcrVPl4ix5ZEj91mUDF0O1t04haD7VZuLVFXVGmqtFrBKI76sdYN-zkokaa1_chPRTyqMQFlqu_8LD6-RiK3UccGM-dEmnX72i91NP9F9OK0WJr9Cheup1C_P0mjqAO4Cb8oIHm0Oxz_mRqv5QbTGJtb3xwPLPuVjVCiE4gGBcuU2ixpSVf5HUF7y1KicVMCKiX9ATCBtg8sTdQZQnPEtHcHHAvdsnDVwev1LGfqA-Gdvg="

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
	proxy, err := New(&config.Config{Options: opts})
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
	want := proxy.state.Load().authenticateURL.String()
	if !strings.Contains(body, want) {
		t.Errorf("handler returned unexpected body: got %v want %s ", body, want)
	}
}

func TestProxy_userInfo(t *testing.T) {
	opts := testOptions(t)
	err := ValidateOptions(opts)
	if err != nil {
		t.Fatal(err)
	}
	proxy, err := New(&config.Config{Options: opts})
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "/.pomerium/sign_out", nil)
	rr := httptest.NewRecorder()
	proxy.userInfo(rr, req)
	if status := rr.Code; status != http.StatusFound {
		t.Errorf("handler returned wrong status code: got %v want %v", status, http.StatusFound)
	}
	body := rr.Body.String()
	want := proxy.state.Load().authenticateURL.String()
	if !strings.Contains(body, want) {
		t.Errorf("handler returned unexpected body: got %v want %s ", body, want)
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
			p, err := New(&config.Config{Options: opts})
			if err != nil {
				t.Fatal(err)
			}
			postForm := url.Values{}
			postForm.Add(urlutil.QueryRedirectURI, tt.redirectURL)
			uri := &url.URL{Path: "/"}

			query, _ := url.ParseQuery(uri.RawQuery)
			if tt.verb == http.MethodGet {
				query.Add(urlutil.QueryRedirectURI, tt.redirectURL)
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

func TestProxy_Callback(t *testing.T) {
	t.Parallel()
	opts := testOptions(t)
	tests := []struct {
		name    string
		options *config.Options

		method string

		scheme string
		host   string
		path   string

		headers map[string]string
		qp      map[string]string

		cipher       encoding.MarshalUnmarshaler
		sessionStore sessions.SessionStore
		wantStatus   int
		wantBody     string
	}{
		{
			"good",
			opts,
			http.MethodGet,
			"http",
			"example.com",
			"/",
			nil,
			map[string]string{urlutil.QueryCallbackURI: "ok", urlutil.QuerySessionEncrypted: goodEncryptionString},
			&mock.Encoder{MarshalResponse: []byte("x")},
			&mstore.Store{Session: &sessions.State{Expiry: jwt.NewNumericDate(time.Now().Add(10 * time.Minute))}},
			http.StatusFound,
			"",
		},
		{
			"good programmatic",
			opts,
			http.MethodGet,
			"http",
			"example.com",
			"/",
			nil,
			map[string]string{urlutil.QueryIsProgrammatic: "true", urlutil.QueryCallbackURI: "ok", urlutil.QuerySessionEncrypted: goodEncryptionString},
			&mock.Encoder{MarshalResponse: []byte("x")},
			&mstore.Store{Session: &sessions.State{Expiry: jwt.NewNumericDate(time.Now().Add(10 * time.Minute))}},
			http.StatusFound,
			"",
		},
		{
			"bad decrypt",
			opts,
			http.MethodGet,
			"http",
			"example.com",
			"/",
			nil,
			map[string]string{urlutil.QuerySessionEncrypted: "KBEjQ9rnCxaAX-GOqexGw9ivEQURqts3zZ2mNGy0wnVa3SbtM399KlBq2nZ-9wM21FfsZX52er4jlmC7kPEKM3P7uZ41zR0zeys1-_74a5tQp-vsf1WXZfRsgVOuBcWPkMiWEoc379JFHxGDudp5VhU8B-dcQt4f3_PtLTHARkuH54io1Va2gNMq4Hiy8sQ1MPGCQeltH_JMzzdDpXdmdusWrXUvCGkba24muvAV06D8XRVJj6Iu9eK94qFnqcHc7wzziEbb8ADBues9dwbtb6jl8vMWz5rN6XvXqA5YpZv_MQZlsrO4oXFFQDevdgB84cX1tVbVu6qZvK_yQBZqzpOjWA9uIaoSENMytoXuWAlFO_sXjswfX8JTNdGwzB7qQRNPqxVG_sM_tzY3QhPm8zqwEzsXG5DokxZfVt2I5WJRUEovFDb4BnK9KFnnkEzLEdMudixVnXeGmTtycgJvoTeTCQRPfDYkcgJ7oKf4tGea-W7z5UAVa2RduJM9ZoM6YtJX7jgDm__PvvqcE0knJUF87XHBzdcOjoDF-CUze9xDJgNBlvPbJqVshKrwoqSYpePSDH9GUCNKxGequW3Ma8GvlFfhwd0rK6IZG-XWkyk0XSWQIGkDSjAvhB1wsOusCCguDjbpVZpaW5MMyTkmx68pl6qlIKT5UCcrVPl4ix5ZEj91mUDF0O1t04haD7VZuLVFXVGmqtFrBKI76sdYN-zkokaa1_chPRTyqMQFlqu_8LD6-RiK3UccGM-dEmnX72i91NP9F9OK0WJr9Cheup1C_P0mjqAO4Cb8oIHm0Oxz_mRqv5QbTGJtb3xwPLPuVjVCiE4gGBcuU2ixpSVf5HUF7y1KicVMCKiX9ATCBtg8sTdQZQnPEtHcHHAvdsnDVwev1LGfqA-Gdvg="},
			&mock.Encoder{MarshalResponse: []byte("x")},
			&mstore.Store{Session: &sessions.State{Expiry: jwt.NewNumericDate(time.Now().Add(10 * time.Minute))}},
			http.StatusBadRequest,
			"",
		},
		{
			"bad save session",
			opts,
			http.MethodGet,
			"http",
			"example.com",
			"/",
			nil,
			map[string]string{urlutil.QuerySessionEncrypted: goodEncryptionString},
			&mock.Encoder{MarshalResponse: []byte("x")},
			&mstore.Store{SaveError: errors.New("hi")},
			http.StatusBadRequest,
			"",
		},
		{
			"bad base64",
			opts,
			http.MethodGet,
			"http",
			"example.com",
			"/",
			nil,
			map[string]string{urlutil.QuerySessionEncrypted: "^"},
			&mock.Encoder{MarshalResponse: []byte("x")},
			&mstore.Store{Session: &sessions.State{Expiry: jwt.NewNumericDate(time.Now().Add(10 * time.Minute))}},
			http.StatusBadRequest,
			"",
		},
		{
			"malformed redirect",
			opts,
			http.MethodGet,
			"http",
			"example.com",
			"/",
			nil,
			nil,
			&mock.Encoder{},
			&mstore.Store{Session: &sessions.State{Expiry: jwt.NewNumericDate(time.Now().Add(10 * time.Minute))}},
			http.StatusBadRequest,
			"",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p, err := New(&config.Config{Options: tt.options})
			if err != nil {
				t.Fatal(err)
			}
			p.OnConfigChange(&config.Config{Options: tt.options})
			state := p.state.Load()
			state.encoder = tt.cipher
			state.sessionStore = tt.sessionStore
			redirectURI := &url.URL{Scheme: tt.scheme, Host: tt.host, Path: tt.path}
			queryString := redirectURI.Query()
			for k, v := range tt.qp {
				queryString.Set(k, v)
			}
			redirectURI.RawQuery = queryString.Encode()

			uri := &url.URL{Path: "/"}
			if tt.qp != nil {
				qu := uri.Query()
				for k, v := range tt.qp {
					qu.Set(k, v)
				}
				qu.Set(urlutil.QueryRedirectURI, redirectURI.String())
				uri.RawQuery = qu.Encode()
			}

			r := httptest.NewRequest(tt.method, uri.String(), nil)

			r.Header.Set("Accept", "application/json")
			if len(tt.headers) != 0 {
				for k, v := range tt.headers {
					r.Header.Set(k, v)
				}
			}

			w := httptest.NewRecorder()
			httputil.HandlerFunc(p.Callback).ServeHTTP(w, r)
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
		options *config.Options

		method string

		scheme  string
		host    string
		path    string
		headers map[string]string
		qp      map[string]string

		wantStatus int
		wantBody   string
	}{
		{
			"good body not checked",
			opts, http.MethodGet, "https", "corp.example.example", "/.pomerium/api/v1/login", nil,
			map[string]string{urlutil.QueryRedirectURI: "http://localhost"},
			http.StatusOK,
			"",
		},
		{
			"good body not checked",
			opts, http.MethodGet, "https", "corp.example.example", "/.pomerium/api/v1/login", nil,
			map[string]string{urlutil.QueryRedirectURI: "http://localhost"},
			http.StatusOK,
			"",
		},
		{
			"router miss, bad redirect_uri query",
			opts, http.MethodGet, "https", "corp.example.example", "/.pomerium/api/v1/login", nil,
			map[string]string{"bad_redirect_uri": "http://localhost"},
			http.StatusNotFound,
			"",
		},
		{
			"bad redirect_uri missing scheme",
			opts, http.MethodGet, "https", "corp.example.example", "/.pomerium/api/v1/login", nil,
			map[string]string{urlutil.QueryRedirectURI: "localhost"},
			http.StatusBadRequest,
			"{\"Status\":400,\"Error\":\"Bad Request: localhost url does contain a valid scheme\"}\n",
		},
		{
			"bad redirect_uri not whitelisted",
			opts, http.MethodGet, "https", "corp.example.example", "/.pomerium/api/v1/login", nil,
			map[string]string{urlutil.QueryRedirectURI: "https://example.com"},
			http.StatusBadRequest,
			"{\"Status\":400,\"Error\":\"Bad Request: invalid redirect uri\"}\n",
		},
		{
			"bad http method",
			opts, http.MethodPost, "https", "corp.example.example", "/.pomerium/api/v1/login", nil,
			map[string]string{urlutil.QueryRedirectURI: "http://localhost"},
			http.StatusMethodNotAllowed,
			"",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p, err := New(&config.Config{Options: tt.options})
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

func TestProxy_ProgrammaticCallback(t *testing.T) {
	t.Parallel()
	opts := testOptions(t)
	tests := []struct {
		name    string
		options *config.Options

		method string

		redirectURI string

		headers map[string]string
		qp      map[string]string

		cipher       encoding.MarshalUnmarshaler
		sessionStore sessions.SessionStore
		wantStatus   int
		wantBody     string
	}{
		{
			"good",
			opts,
			http.MethodGet,
			"http://pomerium.io/",
			nil,
			map[string]string{urlutil.QueryCallbackURI: "ok", urlutil.QuerySessionEncrypted: goodEncryptionString},
			&mock.Encoder{MarshalResponse: []byte("x")},
			&mstore.Store{Session: &sessions.State{Expiry: jwt.NewNumericDate(time.Now().Add(10 * time.Minute))}},
			http.StatusFound,
			"",
		},
		{
			"good programmatic",
			opts,
			http.MethodGet,
			"http://pomerium.io/",
			nil,
			map[string]string{
				urlutil.QueryIsProgrammatic:   "true",
				urlutil.QueryCallbackURI:      "ok",
				urlutil.QuerySessionEncrypted: goodEncryptionString,
			},
			&mock.Encoder{MarshalResponse: []byte("x")},
			&mstore.Store{Session: &sessions.State{Expiry: jwt.NewNumericDate(time.Now().Add(10 * time.Minute))}},
			http.StatusFound,
			"",
		},
		{
			"bad decrypt",
			opts,
			http.MethodGet,
			"http://pomerium.io/",
			nil,
			map[string]string{urlutil.QuerySessionEncrypted: goodEncryptionString + cryptutil.NewBase64Key()},
			&mock.Encoder{MarshalResponse: []byte("x")},
			&mstore.Store{Session: &sessions.State{Expiry: jwt.NewNumericDate(time.Now().Add(10 * time.Minute))}},
			http.StatusBadRequest,
			"",
		},
		{
			"bad save session",
			opts,
			http.MethodGet,
			"http://pomerium.io/",
			nil,
			map[string]string{urlutil.QuerySessionEncrypted: goodEncryptionString},
			&mock.Encoder{MarshalResponse: []byte("x")},
			&mstore.Store{SaveError: errors.New("hi")},
			http.StatusBadRequest,
			"",
		},
		{
			"bad base64",
			opts,
			http.MethodGet,
			"http://pomerium.io/",
			nil,
			map[string]string{urlutil.QuerySessionEncrypted: "^"},
			&mock.Encoder{MarshalResponse: []byte("x")},
			&mstore.Store{Session: &sessions.State{Expiry: jwt.NewNumericDate(time.Now().Add(10 * time.Minute))}},
			http.StatusBadRequest,
			"",
		},
		{
			"malformed redirect",
			opts,
			http.MethodGet,
			"http://pomerium.io/",
			nil,
			nil,
			&mock.Encoder{},
			&mstore.Store{Session: &sessions.State{Expiry: jwt.NewNumericDate(time.Now().Add(10 * time.Minute))}},
			http.StatusBadRequest,
			"",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p, err := New(&config.Config{Options: tt.options})
			if err != nil {
				t.Fatal(err)
			}
			p.OnConfigChange(&config.Config{Options: tt.options})
			state := p.state.Load()
			state.encoder = tt.cipher
			state.sessionStore = tt.sessionStore
			redirectURI, _ := url.Parse(tt.redirectURI)
			queryString := redirectURI.Query()
			for k, v := range tt.qp {
				queryString.Set(k, v)
			}
			redirectURI.RawQuery = queryString.Encode()

			uri := &url.URL{Path: "/"}
			if tt.qp != nil {
				qu := uri.Query()
				for k, v := range tt.qp {
					qu.Set(k, v)
				}
				qu.Set(urlutil.QueryRedirectURI, redirectURI.String())
				uri.RawQuery = qu.Encode()
			}

			r := httptest.NewRequest(tt.method, uri.String(), nil)

			r.Header.Set("Accept", "application/json")
			if len(tt.headers) != 0 {
				for k, v := range tt.headers {
					r.Header.Set(k, v)
				}
			}

			w := httptest.NewRecorder()
			httputil.HandlerFunc(p.Callback).ServeHTTP(w, r)
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

func TestProxy_jwt(t *testing.T) {
	// without upstream headers being set
	req, _ := http.NewRequest("GET", "https://www.example.com/.pomerium/jwt", nil)
	w := httptest.NewRecorder()

	proxy := &Proxy{
		state: newAtomicProxyState(&proxyState{}),
	}
	err := proxy.jwtAssertion(w, req)
	if !assert.Error(t, err) {
		return
	}

	// with upstream request headers being set
	req, _ = http.NewRequest("GET", "https://www.example.com/.pomerium/jwt", nil)
	w = httptest.NewRecorder()
	req.Header.Set(httputil.HeaderPomeriumJWTAssertion, "MOCK_JWT")
	err = proxy.jwtAssertion(w, req)
	if !assert.NoError(t, err) {
		return
	}
	assert.Equal(t, "application/jwt", w.Header().Get("Content-Type"))
	assert.Equal(t, w.Body.String(), "MOCK_JWT")
}
