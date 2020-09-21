package proxy

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

type mockCheckClient struct {
	response *envoy_service_auth_v2.CheckResponse
	err      error
}

func (m *mockCheckClient) Check(ctx context.Context, in *envoy_service_auth_v2.CheckRequest, opts ...grpc.CallOption) (*envoy_service_auth_v2.CheckResponse, error) {
	return m.response, m.err
}

func TestProxy_ForwardAuth(t *testing.T) {
	t.Parallel()

	allowClient := &mockCheckClient{
		response: &envoy_service_auth_v2.CheckResponse{
			Status:       &status.Status{Code: int32(codes.OK), Message: "OK"},
			HttpResponse: &envoy_service_auth_v2.CheckResponse_OkResponse{},
		},
	}

	opts := testOptions(t)
	tests := []struct {
		name     string
		options  *config.Options
		ctxError error
		method   string

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
		{"good redirect not required", opts, nil, http.MethodGet, nil, nil, "https://some.domain.example/", "https://some.domain.example", &mock.Encoder{}, &mstore.Store{Session: &sessions.State{Expiry: jwt.NewNumericDate(time.Now().Add(10 * time.Minute))}}, allowClient, http.StatusOK, "Access to some.domain.example is allowed."},
		{"good verify only, no redirect", opts, nil, http.MethodGet, nil, nil, "https://some.domain.example/verify", "https://some.domain.example", &mock.Encoder{}, &mstore.Store{Session: &sessions.State{Expiry: jwt.NewNumericDate(time.Now().Add(10 * time.Minute))}}, allowClient, http.StatusOK, ""},
		{"bad empty domain uri", opts, nil, http.MethodGet, nil, map[string]string{"uri": ""}, "https://some.domain.example/", "", &mock.Encoder{}, &mstore.Store{Session: &sessions.State{Expiry: jwt.NewNumericDate(time.Now().Add(10 * time.Minute))}}, allowClient, http.StatusBadRequest, "{\"Status\":400,\"Error\":\"Bad Request: no uri to validate\"}\n"},
		{"bad naked domain uri", opts, nil, http.MethodGet, nil, nil, "https://some.domain.example/", "a.naked.domain", &mock.Encoder{}, &mstore.Store{Session: &sessions.State{Expiry: jwt.NewNumericDate(time.Now().Add(10 * time.Minute))}}, allowClient, http.StatusBadRequest, "{\"Status\":400,\"Error\":\"Bad Request: a.naked.domain url does contain a valid scheme\"}\n"},
		{"bad naked domain uri verify only", opts, nil, http.MethodGet, nil, nil, "https://some.domain.example/verify", "a.naked.domain", &mock.Encoder{}, &mstore.Store{Session: &sessions.State{Expiry: jwt.NewNumericDate(time.Now().Add(10 * time.Minute))}}, allowClient, http.StatusBadRequest, "{\"Status\":400,\"Error\":\"Bad Request: a.naked.domain url does contain a valid scheme\"}\n"},
		{"bad empty verification uri", opts, nil, http.MethodGet, nil, nil, "https://some.domain.example/", " ", &mock.Encoder{}, &mstore.Store{Session: &sessions.State{Expiry: jwt.NewNumericDate(time.Now().Add(10 * time.Minute))}}, allowClient, http.StatusBadRequest, "{\"Status\":400,\"Error\":\"Bad Request: %20 url does contain a valid scheme\"}\n"},
		{"bad empty verification uri verify only", opts, nil, http.MethodGet, nil, nil, "https://some.domain.example/verify", " ", &mock.Encoder{}, &mstore.Store{Session: &sessions.State{Expiry: jwt.NewNumericDate(time.Now().Add(10 * time.Minute))}}, allowClient, http.StatusBadRequest, "{\"Status\":400,\"Error\":\"Bad Request: %20 url does contain a valid scheme\"}\n"},
		// traefik
		{"good traefik callback", opts, nil, http.MethodGet, map[string]string{httputil.HeaderForwardedURI: "https://some.domain.example?" + urlutil.QuerySessionEncrypted + "=" + goodEncryptionString}, nil, "https://some.domain.example/", "https://some.domain.example", &mock.Encoder{}, &mstore.Store{Session: &sessions.State{Expiry: jwt.NewNumericDate(time.Now().Add(10 * time.Minute))}}, allowClient, http.StatusFound, ""},
		{"bad traefik callback bad session", opts, nil, http.MethodGet, map[string]string{httputil.HeaderForwardedURI: "https://some.domain.example?" + urlutil.QuerySessionEncrypted + "=" + goodEncryptionString + "garbage"}, nil, "https://some.domain.example/", "https://some.domain.example", &mock.Encoder{}, &mstore.Store{Session: &sessions.State{Expiry: jwt.NewNumericDate(time.Now().Add(10 * time.Minute))}}, allowClient, http.StatusBadRequest, ""},
		{"bad traefik callback bad url", opts, nil, http.MethodGet, map[string]string{httputil.HeaderForwardedURI: urlutil.QuerySessionEncrypted + ""}, nil, "https://some.domain.example/", "https://some.domain.example", &mock.Encoder{}, &mstore.Store{Session: &sessions.State{Expiry: jwt.NewNumericDate(time.Now().Add(10 * time.Minute))}}, allowClient, http.StatusBadRequest, ""},
		{"good traefik verify uri from headers", opts, nil, http.MethodGet, map[string]string{httputil.HeaderForwardedProto: "https", httputil.HeaderForwardedHost: "some.domain.example:8080"}, nil, "https://some.domain.example/", "", &mock.Encoder{}, &mstore.Store{Session: &sessions.State{Expiry: jwt.NewNumericDate(time.Now().Add(10 * time.Minute))}}, allowClient, http.StatusOK, ""},
		{"good traefik verify uri from insecure headers", opts, nil, http.MethodGet, map[string]string{httputil.HeaderForwardedProto: "http", httputil.HeaderForwardedHost: "some.domain.example:8080"}, nil, "https://some.domain.example/", "", &mock.Encoder{}, &mstore.Store{Session: &sessions.State{Expiry: jwt.NewNumericDate(time.Now().Add(10 * time.Minute))}}, allowClient, http.StatusOK, ""},

		// // nginx
		{"good nginx callback redirect", opts, nil, http.MethodGet, nil, map[string]string{urlutil.QueryRedirectURI: "https://some.domain.example/", urlutil.QuerySessionEncrypted: goodEncryptionString}, "https://some.domain.example/", "https://some.domain.example", &mock.Encoder{}, &mstore.Store{Session: &sessions.State{Expiry: jwt.NewNumericDate(time.Now().Add(10 * time.Minute))}}, allowClient, http.StatusFound, ""},
		{"good nginx callback set session okay but return unauthorized", opts, nil, http.MethodGet, nil, map[string]string{urlutil.QueryRedirectURI: "https://some.domain.example/", urlutil.QuerySessionEncrypted: goodEncryptionString}, "https://some.domain.example/verify", "https://some.domain.example", &mock.Encoder{}, &mstore.Store{Session: &sessions.State{Expiry: jwt.NewNumericDate(time.Now().Add(10 * time.Minute))}}, allowClient, http.StatusUnauthorized, ""},
		{"bad nginx callback failed to set session", opts, nil, http.MethodGet, nil, map[string]string{urlutil.QueryRedirectURI: "https://some.domain.example/", urlutil.QuerySessionEncrypted: goodEncryptionString + "nope"}, "https://some.domain.example/verify", "https://some.domain.example", &mock.Encoder{}, &mstore.Store{Session: &sessions.State{Expiry: jwt.NewNumericDate(time.Now().Add(10 * time.Minute))}}, allowClient, http.StatusBadRequest, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p, err := New(&config.Config{Options: tt.options})
			if err != nil {
				t.Fatal(err)
			}
			p.OnConfigChange(&config.Config{Options: tt.options})
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
		})
	}
}
