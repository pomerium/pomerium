package forwardauth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	envoy_service_auth_v2 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v2"
	"github.com/google/go-cmp/cmp"
	"google.golang.org/genproto/googleapis/rpc/status"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"gopkg.in/square/go-jose.v2/jwt"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/encoding"
	"github.com/pomerium/pomerium/internal/encoding/jws"
	"github.com/pomerium/pomerium/internal/encoding/mock"
	"github.com/pomerium/pomerium/internal/httputil"
	"github.com/pomerium/pomerium/internal/sessions"
	mstore "github.com/pomerium/pomerium/internal/sessions/mock"
	"github.com/pomerium/pomerium/internal/urlutil"
)

const goodEncryptionString = "KBEjQ9rnCxaAX-GOqetGw9ivEQURqts3zZ2mNGy0wnVa3SbtM399KlBq2nZ-9wM21FfsZX52er4jlmC7kPEKM3P7uZ41zR0zeys1-_74a5tQp-vsf1WXZfRsgVOuBcWPkMiWEoc379JFHxGDudp5VhU8B-dcQt4f3_PtLTHARkuH54io1Va2gNMq4Hiy8sQ1MPGCQeltH_JMzzdDpXdmdusWrXUvCGkba24muvAV06D8XRVJj6Iu9eK94qFnqcHc7wzziEbb8ADBues9dwbtb6jl8vMWz5rN6XvXqA5YpZv_MQZlsrO4oXFFQDevdgB84cX1tVbVu6qZvK_yQBZqzpOjWA9uIaoSENMytoXuWAlFO_sXjswfX8JTNdGwzB7qQRNPqxVG_sM_tzY3QhPm8zqwEzsXG5DokxZfVt2I5WJRUEovFDb4BnK9KFnnkEzLEdMudixVnXeGmTtycgJvoTeTCQRPfDYkcgJ7oKf4tGea-W7z5UAVa2RduJM9ZoM6YtJX7jgDm__PvvqcE0knJUF87XHBzdcOjoDF-CUze9xDJgNBlvPbJqVshKrwoqSYpePSDH9GUCNKxGequW3Ma8GvlFfhwd0rK6IZG-XWkyk0XSWQIGkDSjAvhB1wsOusCCguDjbpVZpaW5MMyTkmx68pl6qlIKT5UCcrVPl4ix5ZEj91mUDF0O1t04haD7VZuLVFXVGmqtFrBKI76sdYN-zkokaa1_chPRTyqMQFlqu_8LD6-RiK3UccGM-dEmnX72i91NP9F9OK0WJr9Cheup1C_P0mjqAO4Cb8oIHm0Oxz_mRqv5QbTGJtb3xwPLPuVjVCiE4gGBcuU2ixpSVf5HUF7y1KicVMCKiX9ATCBtg8sTdQZQnPEtHcHHAvdsnDVwev1LGfqA-Gdvg="

func testOptions(t *testing.T) *config.Options {
	opts := config.NewDefaultOptions()
	opts.AuthenticateURLString = "https://authenticate.example"
	opts.AuthorizeURLString = "https://authorize.example"
	opts.ForwardAuthURLString = "https://forwardauth.example"
	opts.ForwardAuthType = ForwardingProxyNginx

	testPolicy := config.Policy{From: "https://corp.example.example", To: "https://example.example"}
	opts.Policies = []config.Policy{testPolicy}
	opts.InsecureServer = true
	opts.CookieSecure = false
	opts.Services = config.ServiceAll
	opts.SharedKey = "80ldlrU2d7w+wVpKNfevk6fmb8otEx6CqOfshj2LwhQ="
	opts.CookieSecret = "OromP1gurwGWjQPYb1nNgSxtbVB5NnLzX6z5WOKr0Yw="
	err := opts.Validate()
	if err != nil {
		t.Fatal(err)
	}
	return opts
}

type mockCheckClient struct {
	response *envoy_service_auth_v2.CheckResponse
	err      error
}

func (m *mockCheckClient) Check(ctx context.Context, in *envoy_service_auth_v2.CheckRequest, opts ...grpc.CallOption) (*envoy_service_auth_v2.CheckResponse, error) {
	return m.response, m.err
}

func TestForwardAuth(t *testing.T) {
	t.Parallel()
	allowClient := &mockCheckClient{
		response: &envoy_service_auth_v2.CheckResponse{
			Status:       &status.Status{Code: int32(codes.OK), Message: "OK"},
			HttpResponse: &envoy_service_auth_v2.CheckResponse_OkResponse{},
		},
	}

	tests := []struct {
		name             string
		ForwardAuthTypes []string
		ctxError         error
		method           string

		headers map[string]string
		qp      map[string]string

		requestURI string
		verifyURI  string

		cipher       encoding.MarshalUnmarshaler
		sessionStore sessions.SessionStore
		authorizer   envoy_service_auth_v2.AuthorizationClient
		wantStatus   int
		wantBody     string
	}{
		// Common
		{"good redirect not required", ForwardingProxyTypes, nil, http.MethodGet, nil, nil, "https://some.domain.example/", "https://some.domain.example", &mock.Encoder{}, &mstore.Store{Session: &sessions.State{Expiry: jwt.NewNumericDate(time.Now().Add(10 * time.Minute))}}, allowClient, http.StatusOK, "Access to some.domain.example is allowed."},
		{"bad empty domain uri", ForwardingProxyTypes, nil, http.MethodGet, nil, map[string]string{"uri": ""}, "https://some.domain.example/", "", &mock.Encoder{}, &mstore.Store{Session: &sessions.State{Expiry: jwt.NewNumericDate(time.Now().Add(10 * time.Minute))}}, allowClient, http.StatusBadRequest, "{\"Status\":400,\"Error\":\"Bad Request: no uri to validate\"}\n"},
		{"bad naked domain uri", ForwardingProxyTypes, nil, http.MethodGet, nil, nil, "https://some.domain.example/", "a.naked.domain", &mock.Encoder{}, &mstore.Store{Session: &sessions.State{Expiry: jwt.NewNumericDate(time.Now().Add(10 * time.Minute))}}, allowClient, http.StatusBadRequest, "{\"Status\":400,\"Error\":\"Bad Request: a.naked.domain url does contain a valid scheme\"}\n"},
		{"bad empty verification uri", ForwardingProxyTypes, nil, http.MethodGet, nil, nil, "https://some.domain.example/", " ", &mock.Encoder{}, &mstore.Store{Session: &sessions.State{Expiry: jwt.NewNumericDate(time.Now().Add(10 * time.Minute))}}, allowClient, http.StatusBadRequest, "{\"Status\":400,\"Error\":\"Bad Request: %20 url does contain a valid scheme\"}\n"},

		// traefik
		{"good traefik callback", []string{ForwardingProxyTraefik}, nil, http.MethodGet, map[string]string{httputil.HeaderForwardedURI: "https://some.domain.example?" + urlutil.QuerySessionEncrypted + "=" + goodEncryptionString}, nil, "https://some.domain.example/", "https://some.domain.example", &mock.Encoder{}, &mstore.Store{Session: &sessions.State{Expiry: jwt.NewNumericDate(time.Now().Add(10 * time.Minute))}}, allowClient, http.StatusFound, ""},
		{"bad traefik callback bad session", []string{ForwardingProxyTraefik}, nil, http.MethodGet, map[string]string{httputil.HeaderForwardedURI: "https://some.domain.example?" + urlutil.QuerySessionEncrypted + "=" + goodEncryptionString + "garbage"}, nil, "https://some.domain.example/", "https://some.domain.example", &mock.Encoder{}, &mstore.Store{Session: &sessions.State{Expiry: jwt.NewNumericDate(time.Now().Add(10 * time.Minute))}}, allowClient, http.StatusBadRequest, ""},
		{"bad traefik callback bad url", []string{ForwardingProxyTraefik}, nil, http.MethodGet, map[string]string{httputil.HeaderForwardedURI: urlutil.QuerySessionEncrypted + ""}, nil, "https://some.domain.example/", "https://some.domain.example", &mock.Encoder{}, &mstore.Store{Session: &sessions.State{Expiry: jwt.NewNumericDate(time.Now().Add(10 * time.Minute))}}, allowClient, http.StatusBadRequest, ""},
		{"good traefik verify uri from headers", []string{ForwardingProxyTraefik}, nil, http.MethodGet, map[string]string{httputil.HeaderForwardedProto: "https", httputil.HeaderForwardedHost: "some.domain.example:8080"}, nil, "https://some.domain.example/", "", &mock.Encoder{}, &mstore.Store{Session: &sessions.State{Expiry: jwt.NewNumericDate(time.Now().Add(10 * time.Minute))}}, allowClient, http.StatusOK, ""},

		// // nginx
		{"good verify only, no redirect", []string{ForwardingProxyNginx}, nil, http.MethodGet, nil, nil, "https://some.domain.example/verify", "https://some.domain.example", &mock.Encoder{}, &mstore.Store{Session: &sessions.State{Expiry: jwt.NewNumericDate(time.Now().Add(10 * time.Minute))}}, allowClient, http.StatusOK, ""},
		{"bad naked domain uri verify only", []string{ForwardingProxyNginx}, nil, http.MethodGet, nil, nil, "https://some.domain.example/verify", "a.naked.domain", &mock.Encoder{}, &mstore.Store{Session: &sessions.State{Expiry: jwt.NewNumericDate(time.Now().Add(10 * time.Minute))}}, allowClient, http.StatusBadRequest, "{\"Status\":400,\"Error\":\"Bad Request: a.naked.domain url does contain a valid scheme\"}\n"},
		{"bad empty verification uri verify only", []string{ForwardingProxyNginx}, nil, http.MethodGet, nil, nil, "https://some.domain.example/verify", " ", &mock.Encoder{}, &mstore.Store{Session: &sessions.State{Expiry: jwt.NewNumericDate(time.Now().Add(10 * time.Minute))}}, allowClient, http.StatusBadRequest, "{\"Status\":400,\"Error\":\"Bad Request: %20 url does contain a valid scheme\"}\n"},
		{"good nginx callback redirect", []string{ForwardingProxyNginx}, nil, http.MethodGet, nil, map[string]string{urlutil.QueryRedirectURI: "https://some.domain.example/", urlutil.QuerySessionEncrypted: goodEncryptionString}, "https://some.domain.example/", "https://some.domain.example", &mock.Encoder{}, &mstore.Store{Session: &sessions.State{Expiry: jwt.NewNumericDate(time.Now().Add(10 * time.Minute))}}, allowClient, http.StatusFound, ""},
		{"good nginx callback set session okay but return unauthorized", []string{ForwardingProxyNginx}, nil, http.MethodGet, nil, map[string]string{urlutil.QueryRedirectURI: "https://some.domain.example/", urlutil.QuerySessionEncrypted: goodEncryptionString}, "https://some.domain.example/verify", "https://some.domain.example", &mock.Encoder{}, &mstore.Store{Session: &sessions.State{Expiry: jwt.NewNumericDate(time.Now().Add(10 * time.Minute))}}, allowClient, http.StatusUnauthorized, ""},
		{"bad nginx callback failed to set session", []string{ForwardingProxyNginx}, nil, http.MethodGet, nil, map[string]string{urlutil.QueryRedirectURI: "https://some.domain.example/", urlutil.QuerySessionEncrypted: goodEncryptionString + "nope"}, "https://some.domain.example/verify", "https://some.domain.example", &mock.Encoder{}, &mstore.Store{Session: &sessions.State{Expiry: jwt.NewNumericDate(time.Now().Add(10 * time.Minute))}}, allowClient, http.StatusBadRequest, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for _, typ := range tt.ForwardAuthTypes {
				opts := testOptions(t)
				opts.ForwardAuthType = typ
				p, err := New(&config.Config{Options: opts})
				if err != nil {
					t.Fatal(err)
				}
				p.OnConfigChange(&config.Config{Options: opts})
				state := p.state.Load()
				state.authzClient = tt.authorizer
				state.sessionStore = tt.sessionStore
				signer, err := jws.NewHS256Signer(nil, "mock")
				if err != nil {
					t.Fatal(err)
				}
				state.encoder = signer
				uri, err := url.Parse(tt.requestURI)
				if err != nil {
					t.Fatal(err)
				}
				queryString := uri.Query()
				for k, v := range tt.qp {
					queryString.Set(k, v)
				}
				if tt.verifyURI != "" {
					queryString.Set("uri", tt.verifyURI)
				}

				uri.RawQuery = queryString.Encode()

				r := httptest.NewRequest(tt.method, uri.String(), nil)
				ss, _ := tt.sessionStore.LoadSession(r)

				ctx := r.Context()
				ctx = sessions.NewContext(ctx, ss, tt.ctxError)
				r = r.WithContext(ctx)
				r.Header.Set("Accept", "application/json")
				if len(tt.headers) != 0 {
					for k, v := range tt.headers {
						r.Header.Set(k, v)
					}
				}
				w := httptest.NewRecorder()
				router := p.registerFwdAuthHandlers()
				router.ServeHTTP(w, r)
				if status := w.Code; status != tt.wantStatus {
					t.Errorf("status code: got %v want %v in %s", status, tt.wantStatus, tt.name)
					t.Errorf("\n%+v", w.Body.String())
				}

				if tt.wantBody != "" {
					body := w.Body.String()
					if diff := cmp.Diff(body, tt.wantBody); diff != "" {
						t.Errorf("wrong body\n%s", diff)
					}
				}
			}
		})
	}
}
