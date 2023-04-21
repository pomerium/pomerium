package proxy

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/assert"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/atomicutil"
	"github.com/pomerium/pomerium/internal/httputil"
	"github.com/pomerium/pomerium/internal/urlutil"
)

func TestProxy_RobotsTxt(t *testing.T) {
	proxy := Proxy{}
	req := httptest.NewRequest(http.MethodGet, "/robots.txt", nil)
	rr := httptest.NewRecorder()
	proxy.RobotsTxt(rr, req)
	if status := rr.Code; status != http.StatusOK {
		t.Errorf("handler returned wrong status code: got %v want %v", status, http.StatusOK)
	}
	expected := "User-agent: *\nDisallow: /"
	if rr.Body.String() != expected {
		t.Errorf("handler returned wrong body: got %v want %v", rr.Body.String(), expected)
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
			u, err := urlutil.ParseAndValidateURL(w.HeaderMap.Get("Location"))
			if assert.NoError(t, err) {
				assert.Equal(t, "/.pomerium/sign_out", u.Path)
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
			"{\"Status\":400}\n",
		},
		{
			"bad redirect_uri not whitelisted",
			opts, http.MethodGet, "https", "corp.example.example", "/.pomerium/api/v1/login", nil,
			map[string]string{urlutil.QueryRedirectURI: "https://example.com"},
			http.StatusBadRequest,
			"{\"Status\":400}\n",
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

func TestProxy_jwt(t *testing.T) {
	// without upstream headers being set
	req, _ := http.NewRequest(http.MethodGet, "https://www.example.com/.pomerium/jwt", nil)
	w := httptest.NewRecorder()

	proxy := &Proxy{
		state: atomicutil.NewValue(&proxyState{}),
	}
	err := proxy.jwtAssertion(w, req)
	if !assert.Error(t, err) {
		return
	}

	// with upstream request headers being set
	rawJWT := "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTY3MDg4OTI0MSwiZXhwIjoxNjcwODkyODQxfQ.YoROB12_-a8VxikPqrYOA576pLYoLFeGwXAOWCGpXgM"
	req, _ = http.NewRequest(http.MethodGet, "https://www.example.com/.pomerium/jwt", nil)
	w = httptest.NewRecorder()
	req.Header.Set(httputil.HeaderPomeriumJWTAssertion, rawJWT)
	err = proxy.jwtAssertion(w, req)
	if !assert.NoError(t, err) {
		return
	}
	assert.Equal(t, "application/jwt", w.Header().Get("Content-Type"))
	assert.Equal(t, w.Body.String(), rawJWT)
}
