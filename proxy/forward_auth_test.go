package proxy

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"gopkg.in/square/go-jose.v2/jwt"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/encoding"
	"github.com/pomerium/pomerium/internal/encoding/mock"
	"github.com/pomerium/pomerium/internal/grpc/authorize/client"
	"github.com/pomerium/pomerium/internal/httputil"
	"github.com/pomerium/pomerium/internal/sessions"
	mstore "github.com/pomerium/pomerium/internal/sessions/mock"
	"github.com/pomerium/pomerium/internal/urlutil"
)

func TestProxy_ForwardAuth(t *testing.T) {
	t.Parallel()
	opts := testOptions(t)
	tests := []struct {
		name     string
		options  config.Options
		ctxError error
		method   string

		headers map[string]string
		qp      map[string]string

		requestURI string
		verifyURI  string

		cipher       encoding.MarshalUnmarshaler
		sessionStore sessions.SessionStore
		authorizer   client.Authorizer
		wantStatus   int
		wantBody     string
	}{
		{"good redirect not required", opts, nil, http.MethodGet, nil, nil, "https://some.domain.example/", "https://some.domain.example", &mock.Encoder{}, &mstore.Store{Session: &sessions.State{Email: "user@test.example", Expiry: jwt.NewNumericDate(time.Now().Add(10 * time.Minute))}}, client.MockAuthorize{AuthorizeResponse: true}, http.StatusOK, "Access to some.domain.example is allowed."},
		{"good verify only, no redirect", opts, nil, http.MethodGet, nil, nil, "https://some.domain.example/verify", "https://some.domain.example", &mock.Encoder{}, &mstore.Store{Session: &sessions.State{Email: "user@test.example", Expiry: jwt.NewNumericDate(time.Now().Add(10 * time.Minute))}}, client.MockAuthorize{AuthorizeResponse: true}, http.StatusOK, ""},
		{"bad claim", opts, nil, http.MethodGet, nil, nil, "/", "https://some.domain.example", &mock.Encoder{}, &mstore.Store{LoadError: sessions.ErrInvalidAudience}, client.MockAuthorize{AuthorizeResponse: true}, http.StatusUnauthorized, "{\"Status\":401,\"Error\":\"Unauthorized: internal/sessions: validation failed, invalid audience claim (aud)\"}\n"},
		{"bad naked domain uri", opts, nil, http.MethodGet, nil, nil, "https://some.domain.example/", "a.naked.domain", &mock.Encoder{}, &mstore.Store{Session: &sessions.State{Email: "user@test.example", Expiry: jwt.NewNumericDate(time.Now().Add(10 * time.Minute))}}, client.MockAuthorize{AuthorizeResponse: true}, http.StatusBadRequest, "{\"Status\":400,\"Error\":\"Bad Request: a.naked.domain url does contain a valid scheme\"}\n"},
		{"bad naked domain uri verify only", opts, nil, http.MethodGet, nil, nil, "https://some.domain.example/verify", "a.naked.domain", &mock.Encoder{}, &mstore.Store{Session: &sessions.State{Email: "user@test.example", Expiry: jwt.NewNumericDate(time.Now().Add(10 * time.Minute))}}, client.MockAuthorize{AuthorizeResponse: true}, http.StatusBadRequest, "{\"Status\":400,\"Error\":\"Bad Request: a.naked.domain url does contain a valid scheme\"}\n"},
		{"bad empty verification uri", opts, nil, http.MethodGet, nil, nil, "https://some.domain.example/", " ", &mock.Encoder{}, &mstore.Store{Session: &sessions.State{Email: "user@test.example", Expiry: jwt.NewNumericDate(time.Now().Add(10 * time.Minute))}}, client.MockAuthorize{AuthorizeResponse: true}, http.StatusBadRequest, "{\"Status\":400,\"Error\":\"Bad Request: %20 url does contain a valid scheme\"}\n"},
		{"bad empty verification uri verify only", opts, nil, http.MethodGet, nil, nil, "https://some.domain.example/verify", " ", &mock.Encoder{}, &mstore.Store{Session: &sessions.State{Email: "user@test.example", Expiry: jwt.NewNumericDate(time.Now().Add(10 * time.Minute))}}, client.MockAuthorize{AuthorizeResponse: true}, http.StatusBadRequest, "{\"Status\":400,\"Error\":\"Bad Request: %20 url does contain a valid scheme\"}\n"},
		{"not authorized", opts, nil, http.MethodGet, nil, nil, "https://some.domain.example/", "https://some.domain.example", &mock.Encoder{}, &mstore.Store{Session: &sessions.State{Email: "user@test.example", Expiry: jwt.NewNumericDate(time.Now().Add(10 * time.Minute))}}, client.MockAuthorize{AuthorizeResponse: false}, http.StatusForbidden, "{\"Status\":403,\"Error\":\"Forbidden: user@test.example is not authorized for some.domain.example\"}\n"},
		{"not authorized verify endpoint", opts, nil, http.MethodGet, nil, nil, "https://some.domain.example/verify", "https://some.domain.example", &mock.Encoder{}, &mstore.Store{Session: &sessions.State{Email: "user@test.example", Expiry: jwt.NewNumericDate(time.Now().Add(10 * time.Minute))}}, client.MockAuthorize{AuthorizeResponse: false}, http.StatusForbidden, "{\"Status\":403,\"Error\":\"Forbidden: user@test.example is not authorized for some.domain.example\"}\n"},
		{"not authorized expired, redirect to auth", opts, sessions.ErrExpired, http.MethodGet, nil, nil, "https://some.domain.example/", "https://some.domain.example", &mock.Encoder{}, &mstore.Store{Session: &sessions.State{Email: "user@test.example", Expiry: jwt.NewNumericDate(time.Now().Add(-10 * time.Minute))}}, client.MockAuthorize{AuthorizeResponse: false}, http.StatusFound, ""},
		{"not authorized expired, don't redirect!", opts, sessions.ErrExpired, http.MethodGet, nil, nil, "https://some.domain.example/verify", "https://some.domain.example", &mock.Encoder{}, &mstore.Store{Session: &sessions.State{Email: "user@test.example", Expiry: jwt.NewNumericDate(time.Now().Add(-10 * time.Minute))}}, client.MockAuthorize{AuthorizeResponse: false}, http.StatusUnauthorized, "{\"Status\":401,\"Error\":\"Unauthorized: internal/sessions: validation failed, token is expired (exp)\"}\n"},
		{"not authorized because of error", opts, nil, http.MethodGet, nil, nil, "https://some.domain.example/", "https://some.domain.example", &mock.Encoder{}, &mstore.Store{Session: &sessions.State{Email: "user@test.example", Expiry: jwt.NewNumericDate(time.Now().Add(10 * time.Minute))}}, client.MockAuthorize{AuthorizeError: errors.New("authz error")}, http.StatusInternalServerError, "{\"Status\":500,\"Error\":\"Internal Server Error: authz error\"}\n"},
		{"not authorized expired, do not redirect to auth", opts, nil, http.MethodGet, nil, nil, "https://some.domain.example/verify", "https://some.domain.example", &mock.Encoder{}, &mstore.Store{Session: &sessions.State{Email: "user@test.example", Expiry: jwt.NewNumericDate(time.Now().Add(-10 * time.Minute))}}, client.MockAuthorize{AuthorizeResponse: false}, http.StatusUnauthorized, "{\"Status\":401,\"Error\":\"Unauthorized: internal/sessions: validation failed, token is expired (exp)\"}\n"},
		{"not authorized, bad audience request uri", opts, nil, http.MethodGet, nil, nil, "https://some.domain.example/", "https://some.domain.example", &mock.Encoder{}, &mstore.Store{Session: &sessions.State{Audience: []string{"not.domain.example"}, Email: "user@test.example", Expiry: jwt.NewNumericDate(time.Now().Add(10 * time.Minute))}}, client.MockAuthorize{AuthorizeResponse: true}, http.StatusUnauthorized, "{\"Status\":401,\"Error\":\"Unauthorized: internal/sessions: validation failed, invalid audience claim (aud)\"}\n"},
		{"not authorized, bad audience verify uri", opts, nil, http.MethodGet, nil, nil, "https://some.domain.example/", "https://fwdauth.domain.example", &mock.Encoder{}, &mstore.Store{Session: &sessions.State{Audience: []string{"some.domain.example"}, Email: "user@test.example", Expiry: jwt.NewNumericDate(time.Now().Add(10 * time.Minute))}}, client.MockAuthorize{AuthorizeResponse: true}, http.StatusUnauthorized, "{\"Status\":401,\"Error\":\"Unauthorized: internal/sessions: validation failed, invalid audience claim (aud)\"}\n"},
		// traefik
		{"good traefik callback", opts, nil, http.MethodGet, map[string]string{httputil.HeaderForwardedURI: "https://some.domain.example?" + urlutil.QuerySessionEncrypted + "=" + goodEncryptionString}, nil, "https://some.domain.example/", "https://some.domain.example", &mock.Encoder{}, &mstore.Store{Session: &sessions.State{Email: "user@test.example", Expiry: jwt.NewNumericDate(time.Now().Add(10 * time.Minute))}}, client.MockAuthorize{AuthorizeResponse: true}, http.StatusFound, ""},
		{"bad traefik callback bad session", opts, nil, http.MethodGet, map[string]string{httputil.HeaderForwardedURI: "https://some.domain.example?" + urlutil.QuerySessionEncrypted + "=" + goodEncryptionString + "garbage"}, nil, "https://some.domain.example/", "https://some.domain.example", &mock.Encoder{}, &mstore.Store{Session: &sessions.State{Email: "user@test.example", Expiry: jwt.NewNumericDate(time.Now().Add(10 * time.Minute))}}, client.MockAuthorize{AuthorizeResponse: true}, http.StatusBadRequest, ""},
		{"bad traefik callback bad url", opts, nil, http.MethodGet, map[string]string{httputil.HeaderForwardedURI: urlutil.QuerySessionEncrypted + ""}, nil, "https://some.domain.example/", "https://some.domain.example", &mock.Encoder{}, &mstore.Store{Session: &sessions.State{Email: "user@test.example", Expiry: jwt.NewNumericDate(time.Now().Add(10 * time.Minute))}}, client.MockAuthorize{AuthorizeResponse: true}, http.StatusBadRequest, ""},
		// nginx
		{"good nginx callback redirect", opts, nil, http.MethodGet, nil, map[string]string{urlutil.QueryRedirectURI: "https://some.domain.example/", urlutil.QuerySessionEncrypted: goodEncryptionString}, "https://some.domain.example/", "https://some.domain.example", &mock.Encoder{}, &mstore.Store{Session: &sessions.State{Email: "user@test.example", Expiry: jwt.NewNumericDate(time.Now().Add(10 * time.Minute))}}, client.MockAuthorize{AuthorizeResponse: true}, http.StatusFound, ""},
		{"good nginx callback set session okay but return unauthorized", opts, nil, http.MethodGet, nil, map[string]string{urlutil.QueryRedirectURI: "https://some.domain.example/", urlutil.QuerySessionEncrypted: goodEncryptionString}, "https://some.domain.example/verify", "https://some.domain.example", &mock.Encoder{}, &mstore.Store{Session: &sessions.State{Email: "user@test.example", Expiry: jwt.NewNumericDate(time.Now().Add(10 * time.Minute))}}, client.MockAuthorize{AuthorizeResponse: true}, http.StatusUnauthorized, ""},
		{"bad nginx callback failed to set session", opts, nil, http.MethodGet, nil, map[string]string{urlutil.QueryRedirectURI: "https://some.domain.example/", urlutil.QuerySessionEncrypted: goodEncryptionString + "nope"}, "https://some.domain.example/verify", "https://some.domain.example", &mock.Encoder{}, &mstore.Store{Session: &sessions.State{Email: "user@test.example", Expiry: jwt.NewNumericDate(time.Now().Add(10 * time.Minute))}}, client.MockAuthorize{AuthorizeResponse: true}, http.StatusBadRequest, ""},
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
			state, _ := tt.sessionStore.LoadSession(r)

			ctx := r.Context()
			ctx = sessions.NewContext(ctx, state, tt.ctxError)
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
