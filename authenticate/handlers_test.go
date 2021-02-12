package authenticate

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"html/template"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/golang/protobuf/ptypes"
	"github.com/golang/protobuf/ptypes/empty"
	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/assert"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/oauth2"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"
	"gopkg.in/square/go-jose.v2/jwt"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/encoding"
	"github.com/pomerium/pomerium/internal/encoding/jws"
	"github.com/pomerium/pomerium/internal/encoding/mock"
	"github.com/pomerium/pomerium/internal/frontend"
	"github.com/pomerium/pomerium/internal/httputil"
	"github.com/pomerium/pomerium/internal/identity"
	"github.com/pomerium/pomerium/internal/identity/oidc"
	"github.com/pomerium/pomerium/internal/sessions"
	mstore "github.com/pomerium/pomerium/internal/sessions/mock"
	"github.com/pomerium/pomerium/internal/urlutil"
	"github.com/pomerium/pomerium/pkg/cryptutil"
	"github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/grpc/directory"
	"github.com/pomerium/pomerium/pkg/grpc/session"
)

func testAuthenticate() *Authenticate {
	redirectURL, _ := url.Parse("https://auth.example.com/oauth/callback")
	var auth Authenticate
	auth.state = newAtomicAuthenticateState(&authenticateState{
		redirectURL:  redirectURL,
		cookieSecret: cryptutil.NewKey(),
	})
	auth.templates = template.Must(frontend.NewTemplates())
	auth.options = config.NewAtomicOptions()
	auth.options.Store(&config.Options{
		SharedKey: cryptutil.NewBase64Key(),
	})
	return &auth
}

func TestAuthenticate_RobotsTxt(t *testing.T) {
	auth := testAuthenticate()
	req, err := http.NewRequest("GET", "/robots.txt", nil)
	if err != nil {
		t.Fatal(err)
	}
	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(auth.RobotsTxt)
	handler.ServeHTTP(rr, req)
	if status := rr.Code; status != http.StatusOK {
		t.Errorf("handler returned wrong status code: got %v want %v", status, http.StatusOK)
	}
	expected := fmt.Sprintf("User-agent: *\nDisallow: /")
	if rr.Body.String() != expected {
		t.Errorf("handler returned wrong body: got %v want %v", rr.Body.String(), expected)
	}
}

func TestAuthenticate_Handler(t *testing.T) {
	auth := testAuthenticate()

	h := auth.Handler()
	if h == nil {
		t.Error("handler cannot be nil")
	}
	req := httptest.NewRequest("GET", "/robots.txt", nil)
	req.Header.Set("Accept", "application/json")

	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	expected := fmt.Sprintf("User-agent: *\nDisallow: /")

	body := rr.Body.String()
	if body != expected {
		t.Errorf("handler returned unexpected body: got %v want %v", body, expected)
	}

	// cors preflight
	req = httptest.NewRequest(http.MethodOptions, "/.pomerium/sign_in", nil)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Access-Control-Request-Method", "GET")
	req.Header.Set("Access-Control-Request-Headers", "X-Requested-With")
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	expected = fmt.Sprintf("User-agent: *\nDisallow: /")
	code := rr.Code
	if code != http.StatusOK {
		t.Errorf("bad preflight code %v", code)
	}
	resp := rr.Result()
	body = resp.Header.Get("vary")
	if body == "" {
		t.Errorf("handler returned unexpected body: got %v want %v", body, expected)
	}
}

func TestAuthenticate_SignIn(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string

		scheme string
		host   string
		qp     map[string]string

		session  sessions.SessionStore
		provider identity.MockProvider
		encoder  encoding.MarshalUnmarshaler
		wantCode int
	}{
		{"good", "https", "corp.example.example", map[string]string{urlutil.QueryRedirectURI: "https://dst.some.example/"}, &mstore.Store{Session: &sessions.State{}}, identity.MockProvider{}, &mock.Encoder{}, http.StatusFound},
		{"good alternate port", "https", "corp.example.example:8443", map[string]string{urlutil.QueryRedirectURI: "https://dst.some.example/"}, &mstore.Store{Session: &sessions.State{}}, identity.MockProvider{}, &mock.Encoder{}, http.StatusFound},
		{"session not valid", "https", "corp.example.example", map[string]string{urlutil.QueryRedirectURI: "https://dst.some.example/"}, &mstore.Store{Session: &sessions.State{}}, identity.MockProvider{}, &mock.Encoder{}, http.StatusFound},
		{"bad redirect uri query", "", "corp.example.example", map[string]string{urlutil.QueryRedirectURI: "^^^"}, &mstore.Store{Session: &sessions.State{}}, identity.MockProvider{}, &mock.Encoder{}, http.StatusBadRequest},
		{"bad marshal", "https", "corp.example.example", map[string]string{urlutil.QueryRedirectURI: "https://dst.some.example/"}, &mstore.Store{Session: &sessions.State{}}, identity.MockProvider{}, &mock.Encoder{MarshalError: errors.New("error")}, http.StatusBadRequest},
		{"session error", "https", "corp.example.example", map[string]string{urlutil.QueryRedirectURI: "https://dst.some.example/"}, &mstore.Store{LoadError: errors.New("error")}, identity.MockProvider{}, &mock.Encoder{}, http.StatusBadRequest},
		{"good with different programmatic redirect", "https", "corp.example.example", map[string]string{urlutil.QueryRedirectURI: "https://dst.some.example/", urlutil.QueryCallbackURI: "https://some.example"}, &mstore.Store{Session: &sessions.State{}}, identity.MockProvider{}, &mock.Encoder{}, http.StatusFound},
		{"encrypted encoder error", "https", "corp.example.example", map[string]string{urlutil.QueryRedirectURI: "https://dst.some.example/", urlutil.QueryCallbackURI: "https://some.example"}, &mstore.Store{Session: &sessions.State{}}, identity.MockProvider{}, &mock.Encoder{MarshalError: errors.New("error")}, http.StatusBadRequest},
		{"good with callback uri set", "https", "corp.example.example", map[string]string{urlutil.QueryCallbackURI: "https://some.example/", urlutil.QueryRedirectURI: "https://dst.some.example/"}, &mstore.Store{Session: &sessions.State{}}, identity.MockProvider{}, &mock.Encoder{}, http.StatusFound},
		{"bad callback uri set", "https", "corp.example.example", map[string]string{urlutil.QueryCallbackURI: "^", urlutil.QueryRedirectURI: "https://dst.some.example/"}, &mstore.Store{Session: &sessions.State{}}, identity.MockProvider{}, &mock.Encoder{}, http.StatusBadRequest},
		{"good programmatic request", "https", "corp.example.example", map[string]string{urlutil.QueryIsProgrammatic: "true", urlutil.QueryRedirectURI: "https://dst.some.example/"}, &mstore.Store{Session: &sessions.State{}}, identity.MockProvider{}, &mock.Encoder{}, http.StatusFound},
		{"good additional audience", "https", "corp.example.example", map[string]string{urlutil.QueryForwardAuth: "x.y.z", urlutil.QueryRedirectURI: "https://dst.some.example/"}, &mstore.Store{Session: &sessions.State{}}, identity.MockProvider{}, &mock.Encoder{}, http.StatusFound},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			sharedCipher, _ := cryptutil.NewAEADCipherFromBase64(cryptutil.NewBase64Key())

			a := &Authenticate{
				state: newAtomicAuthenticateState(&authenticateState{
					sharedCipher:     sharedCipher,
					sessionStore:     tt.session,
					redirectURL:      uriParseHelper("https://some.example"),
					sharedEncoder:    tt.encoder,
					encryptedEncoder: tt.encoder,
					dataBrokerClient: mockDataBrokerServiceClient{
						get: func(ctx context.Context, in *databroker.GetRequest, opts ...grpc.CallOption) (*databroker.GetResponse, error) {
							data, err := ptypes.MarshalAny(&session.Session{
								Id: "SESSION_ID",
							})
							if err != nil {
								return nil, err
							}

							return &databroker.GetResponse{
								Record: &databroker.Record{
									Version: "0001",
									Type:    data.GetTypeUrl(),
									Id:      "SESSION_ID",
									Data:    data,
								},
							}, nil
						},
					},
					directoryClient: new(mockDirectoryServiceClient),
				}),

				options:  config.NewAtomicOptions(),
				provider: identity.NewAtomicAuthenticator(),
			}
			a.options.Store(&config.Options{SharedKey: base64.StdEncoding.EncodeToString(cryptutil.NewKey())})
			a.provider.Store(tt.provider)
			uri := &url.URL{Scheme: tt.scheme, Host: tt.host}

			queryString := uri.Query()
			for k, v := range tt.qp {
				queryString.Set(k, v)
			}
			uri.RawQuery = queryString.Encode()
			r := httptest.NewRequest(http.MethodGet, uri.String(), nil)
			r.Header.Set("Accept", "application/json")
			state, err := tt.session.LoadSession(r)
			ctx := r.Context()
			ctx = sessions.NewContext(ctx, state, err)
			r = r.WithContext(ctx)

			w := httptest.NewRecorder()
			httputil.HandlerFunc(a.SignIn).ServeHTTP(w, r)
			if status := w.Code; status != tt.wantCode {
				t.Errorf("handler returned wrong status code: got %v want %v %s", status, tt.wantCode, uri)
				t.Errorf("\n%+v", w.Body)
			}
		})
	}
}

func uriParseHelper(s string) *url.URL {
	uri, _ := url.Parse(s)
	return uri
}

func TestAuthenticate_SignOut(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		method string

		ctxError           error
		redirectURL        string
		signoutRedirectURL string
		sig                string
		ts                 string

		provider     identity.Authenticator
		sessionStore sessions.SessionStore
		wantCode     int
		wantBody     string
	}{
		{"good post", http.MethodPost, nil, "https://corp.pomerium.io/", "", "sig", "ts", identity.MockProvider{LogOutResponse: (*uriParseHelper("https://microsoft.com"))}, &mstore.Store{Encrypted: true, Session: &sessions.State{}}, http.StatusFound, ""},
		{"signout redirect url", http.MethodPost, nil, "", "https://signout-redirect-url.example.com", "sig", "ts", identity.MockProvider{LogOutResponse: (*uriParseHelper("https://microsoft.com"))}, &mstore.Store{Encrypted: true, Session: &sessions.State{}}, http.StatusFound, ""},
		{"failed revoke", http.MethodPost, nil, "https://corp.pomerium.io/", "", "sig", "ts", identity.MockProvider{RevokeError: errors.New("OH NO")}, &mstore.Store{Encrypted: true, Session: &sessions.State{}}, http.StatusFound, ""},
		{"load session error", http.MethodPost, errors.New("error"), "https://corp.pomerium.io/", "", "sig", "ts", identity.MockProvider{RevokeError: errors.New("OH NO")}, &mstore.Store{Encrypted: true, Session: &sessions.State{}}, http.StatusFound, ""},
		{"bad redirect uri", http.MethodPost, nil, "corp.pomerium.io/", "", "sig", "ts", identity.MockProvider{LogOutError: oidc.ErrSignoutNotImplemented}, &mstore.Store{Encrypted: true, Session: &sessions.State{}}, http.StatusFound, ""},
		{"no redirect uri", http.MethodPost, nil, "", "", "sig", "ts", identity.MockProvider{LogOutResponse: (*uriParseHelper("https://microsoft.com"))}, &mstore.Store{Encrypted: true, Session: &sessions.State{}}, http.StatusOK, "{\"Status\":200,\"Error\":\"OK: user logged out\"}\n"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()
			a := &Authenticate{
				state: newAtomicAuthenticateState(&authenticateState{
					sessionStore:     tt.sessionStore,
					encryptedEncoder: mock.Encoder{},
					sharedEncoder:    mock.Encoder{},
					dataBrokerClient: mockDataBrokerServiceClient{
						delete: func(ctx context.Context, in *databroker.DeleteRequest, opts ...grpc.CallOption) (*emptypb.Empty, error) {
							return nil, nil
						},
						get: func(ctx context.Context, in *databroker.GetRequest, opts ...grpc.CallOption) (*databroker.GetResponse, error) {
							data, err := ptypes.MarshalAny(&session.Session{
								Id: "SESSION_ID",
							})
							if err != nil {
								return nil, err
							}

							return &databroker.GetResponse{
								Record: &databroker.Record{
									Version: "0001",
									Type:    data.GetTypeUrl(),
									Id:      "SESSION_ID",
									Data:    data,
								},
							}, nil
						},
					},
					directoryClient: new(mockDirectoryServiceClient),
				}),
				templates: template.Must(frontend.NewTemplates()),
				options:   config.NewAtomicOptions(),
				provider:  identity.NewAtomicAuthenticator(),
			}
			if tt.signoutRedirectURL != "" {
				opts := a.options.Load()
				opts.SignOutRedirectURL, _ = url.Parse(tt.signoutRedirectURL)
				a.options.Store(opts)
			}
			a.provider.Store(tt.provider)
			u, _ := url.Parse("/sign_out")
			params, _ := url.ParseQuery(u.RawQuery)
			params.Add("sig", tt.sig)
			params.Add("ts", tt.ts)
			params.Add(urlutil.QueryRedirectURI, tt.redirectURL)
			u.RawQuery = params.Encode()
			r := httptest.NewRequest(tt.method, u.String(), nil)
			state, err := tt.sessionStore.LoadSession(r)
			if err != nil {
				t.Fatal(err)
			}
			ctx := r.Context()
			ctx = sessions.NewContext(ctx, state, tt.ctxError)
			r = r.WithContext(ctx)
			r.Header.Set("Accept", "application/json")

			w := httptest.NewRecorder()
			httputil.HandlerFunc(a.SignOut).ServeHTTP(w, r)
			if status := w.Code; status != tt.wantCode {
				t.Errorf("handler returned wrong status code: got %v want %v", status, tt.wantCode)
			}
			body := w.Body.String()
			if diff := cmp.Diff(body, tt.wantBody); diff != "" {
				t.Errorf("handler returned wrong body Body: %s", diff)
			}
			if tt.signoutRedirectURL != "" {
				loc := w.Header().Get("Location")
				assert.Contains(t, loc, url.QueryEscape(tt.signoutRedirectURL))
			}
		})
	}
}

func TestAuthenticate_OAuthCallback(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		method string

		ts            int64
		stateOvveride string
		extraMac      string
		extraState    string
		paramErr      string
		code          string
		redirectURI   string

		authenticateURL string
		session         sessions.SessionStore
		provider        identity.MockProvider

		want     string
		wantCode int
	}{
		{"good", http.MethodGet, time.Now().Unix(), "", "", "", "", "code", "https://corp.pomerium.io", "https://authenticate.pomerium.io", &mstore.Store{}, identity.MockProvider{AuthenticateResponse: oauth2.Token{}}, "https://corp.pomerium.io", http.StatusFound},
		{"failed authenticate", http.MethodGet, time.Now().Unix(), "", "", "", "", "code", "https://corp.pomerium.io", "https://authenticate.pomerium.io", &mstore.Store{}, identity.MockProvider{AuthenticateResponse: oauth2.Token{}, AuthenticateError: errors.New("error")}, "", http.StatusInternalServerError},
		{"failed save session", http.MethodGet, time.Now().Unix(), "", "", "", "", "code", "https://corp.pomerium.io", "https://authenticate.pomerium.io", &mstore.Store{SaveError: errors.New("error")}, identity.MockProvider{}, "", http.StatusInternalServerError},
		{"provider returned error", http.MethodGet, time.Now().Unix(), "", "", "", "idp error", "code", "https://corp.pomerium.io", "https://authenticate.pomerium.io", &mstore.Store{}, identity.MockProvider{AuthenticateResponse: oauth2.Token{}}, "", http.StatusBadRequest},
		{"provider returned error imply 401", http.MethodGet, time.Now().Unix(), "", "", "", "access_denied", "code", "https://corp.pomerium.io", "https://authenticate.pomerium.io", &mstore.Store{}, identity.MockProvider{AuthenticateResponse: oauth2.Token{}}, "", http.StatusUnauthorized},
		{"empty code", http.MethodGet, time.Now().Unix(), "", "", "", "", "", "https://corp.pomerium.io", "https://authenticate.pomerium.io", &mstore.Store{}, identity.MockProvider{AuthenticateResponse: oauth2.Token{}}, "", http.StatusBadRequest},
		{"invalid redirect uri", http.MethodGet, time.Now().Unix(), "", "", "", "", "code", "corp.pomerium.io", "https://authenticate.pomerium.io", &mstore.Store{}, identity.MockProvider{AuthenticateResponse: oauth2.Token{}}, "", http.StatusBadRequest},
		{"bad redirect uri", http.MethodGet, time.Now().Unix(), "", "", "", "", "code", "http://^^^", "https://authenticate.pomerium.io", &mstore.Store{}, identity.MockProvider{AuthenticateResponse: oauth2.Token{}}, "https://corp.pomerium.io", http.StatusBadRequest},
		{"bad timing - too soon", http.MethodGet, time.Now().Add(1 * time.Hour).Unix(), "", "", "", "", "code", "https://corp.pomerium.io", "https://authenticate.pomerium.io", &mstore.Store{}, identity.MockProvider{AuthenticateResponse: oauth2.Token{}}, "https://corp.pomerium.io", http.StatusBadRequest},
		{"bad timing - expired", http.MethodGet, time.Now().Add(-1 * time.Hour).Unix(), "", "", "", "", "code", "https://corp.pomerium.io", "https://authenticate.pomerium.io", &mstore.Store{}, identity.MockProvider{AuthenticateResponse: oauth2.Token{}}, "https://corp.pomerium.io", http.StatusBadRequest},
		{"bad base64", http.MethodGet, time.Now().Unix(), "", "", "^", "", "code", "https://corp.pomerium.io", "https://authenticate.pomerium.io", &mstore.Store{}, identity.MockProvider{AuthenticateResponse: oauth2.Token{}}, "https://corp.pomerium.io", http.StatusBadRequest},
		{"too many seperators", http.MethodGet, time.Now().Unix(), "", "", "|ok|now|what", "", "code", "https://corp.pomerium.io", "https://authenticate.pomerium.io", &mstore.Store{}, identity.MockProvider{AuthenticateResponse: oauth2.Token{}}, "https://corp.pomerium.io", http.StatusBadRequest},
		{"bad hmac", http.MethodGet, time.Now().Unix(), "", "NOTMAC", "", "", "code", "https://corp.pomerium.io", "https://authenticate.pomerium.io", &mstore.Store{}, identity.MockProvider{AuthenticateResponse: oauth2.Token{}}, "https://corp.pomerium.io", http.StatusBadRequest},
		{"bad hmac", http.MethodGet, time.Now().Unix(), base64.URLEncoding.EncodeToString([]byte("malformed_state")), "", "", "", "code", "https://corp.pomerium.io", "https://authenticate.pomerium.io", &mstore.Store{}, identity.MockProvider{AuthenticateResponse: oauth2.Token{}}, "https://corp.pomerium.io", http.StatusBadRequest},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()
			aead, err := chacha20poly1305.NewX(cryptutil.NewKey())
			if err != nil {
				t.Fatal(err)
			}
			signer, err := jws.NewHS256Signer(nil)
			if err != nil {
				t.Fatal(err)
			}
			authURL, _ := url.Parse(tt.authenticateURL)
			a := &Authenticate{
				state: newAtomicAuthenticateState(&authenticateState{
					dataBrokerClient: mockDataBrokerServiceClient{
						get: func(ctx context.Context, in *databroker.GetRequest, opts ...grpc.CallOption) (*databroker.GetResponse, error) {
							return nil, fmt.Errorf("not implemented")
						},
						set: func(ctx context.Context, in *databroker.SetRequest, opts ...grpc.CallOption) (*databroker.SetResponse, error) {
							return &databroker.SetResponse{Record: &databroker.Record{Data: in.Data}}, nil
						},
					},
					directoryClient:  new(mockDirectoryServiceClient),
					redirectURL:      authURL,
					sessionStore:     tt.session,
					cookieCipher:     aead,
					encryptedEncoder: signer,
				}),
				options:  config.NewAtomicOptions(),
				provider: identity.NewAtomicAuthenticator(),
			}
			a.provider.Store(tt.provider)
			u, _ := url.Parse("/oauthGet")
			params, _ := url.ParseQuery(u.RawQuery)
			params.Add("error", tt.paramErr)
			params.Add("code", tt.code)
			nonce := cryptutil.NewBase64Key() // mock csrf
			// (nonce|timestamp|redirect_url|encrypt(redirect_url),mac(nonce,ts))
			b := []byte(fmt.Sprintf("%s|%d|%s", nonce, tt.ts, tt.extraMac))

			enc := cryptutil.Encrypt(a.state.Load().cookieCipher, []byte(tt.redirectURI), b)
			b = append(b, enc...)
			encodedState := base64.URLEncoding.EncodeToString(b)
			if tt.extraState != "" {
				encodedState += tt.extraState
			}
			if tt.stateOvveride != "" {
				encodedState = tt.stateOvveride
			}
			params.Add("state", encodedState)

			u.RawQuery = params.Encode()

			r := httptest.NewRequest(tt.method, u.String(), nil)
			r.Header.Set("Accept", "application/json")
			w := httptest.NewRecorder()
			httputil.HandlerFunc(a.OAuthCallback).ServeHTTP(w, r)
			if w.Result().StatusCode != tt.wantCode {
				t.Errorf("Authenticate.OAuthCallback() error = %v, wantErr %v\n%v", w.Result().StatusCode, tt.wantCode, w.Body.String())
				return
			}
		})
	}
}

func TestAuthenticate_SessionValidatorMiddleware(t *testing.T) {
	t.Parallel()
	fn := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		fmt.Fprintln(w, "RVSI FILIVS CAISAR")
		w.WriteHeader(http.StatusOK)
	})

	tests := []struct {
		name    string
		headers map[string]string

		session  sessions.SessionStore
		ctxError error
		provider identity.Authenticator

		wantStatus int
	}{
		{
			"good",
			nil,
			&mstore.Store{Session: &sessions.State{Version: "v1", ID: "xyz", Expiry: jwt.NewNumericDate(time.Now().Add(10 * time.Minute))}},
			nil,
			identity.MockProvider{RefreshResponse: oauth2.Token{Expiry: time.Now().Add(10 * time.Minute)}},
			http.StatusOK,
		},
		{
			"invalid session",
			nil,
			&mstore.Store{Session: &sessions.State{Version: "v1", ID: "xyz", Expiry: jwt.NewNumericDate(time.Now().Add(10 * time.Minute))}},
			errors.New("hi"),
			identity.MockProvider{},
			http.StatusFound,
		},
		{
			"good refresh expired",
			nil,
			&mstore.Store{Session: &sessions.State{Version: "v1", ID: "xyz", Expiry: jwt.NewNumericDate(time.Now().Add(-10 * time.Minute))}},
			nil,
			identity.MockProvider{RefreshResponse: oauth2.Token{Expiry: time.Now().Add(10 * time.Minute)}},
			http.StatusOK,
		},
		{
			"expired,refresh error",
			nil,
			&mstore.Store{Session: &sessions.State{Version: "v1", ID: "xyz", Expiry: jwt.NewNumericDate(time.Now().Add(-10 * time.Minute))}},
			sessions.ErrExpired,
			identity.MockProvider{RefreshError: errors.New("error")},
			http.StatusFound,
		},
		{
			"expired,save error",
			nil,
			&mstore.Store{SaveError: errors.New("error"), Session: &sessions.State{Version: "v1", ID: "xyz", Expiry: jwt.NewNumericDate(time.Now().Add(-10 * time.Minute))}},
			sessions.ErrExpired,
			identity.MockProvider{RefreshResponse: oauth2.Token{Expiry: time.Now().Add(10 * time.Minute)}},
			http.StatusFound,
		},
		{
			"expired XHR,refresh error",
			map[string]string{"X-Requested-With": "XmlHttpRequest"},
			&mstore.Store{Session: &sessions.State{Version: "v1", ID: "xyz", Expiry: jwt.NewNumericDate(time.Now().Add(-10 * time.Minute))}},
			sessions.ErrExpired,
			identity.MockProvider{RefreshError: errors.New("error")},
			http.StatusUnauthorized,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			aead, err := chacha20poly1305.NewX(cryptutil.NewKey())
			if err != nil {
				t.Fatal(err)
			}
			signer, err := jws.NewHS256Signer(nil)
			if err != nil {
				t.Fatal(err)
			}
			a := Authenticate{
				state: newAtomicAuthenticateState(&authenticateState{
					cookieSecret:     cryptutil.NewKey(),
					redirectURL:      uriParseHelper("https://authenticate.corp.beyondperimeter.com"),
					sessionStore:     tt.session,
					cookieCipher:     aead,
					encryptedEncoder: signer,
					sharedEncoder:    signer,
					dataBrokerClient: mockDataBrokerServiceClient{
						get: func(ctx context.Context, in *databroker.GetRequest, opts ...grpc.CallOption) (*databroker.GetResponse, error) {
							data, err := ptypes.MarshalAny(&session.Session{
								Id: "SESSION_ID",
							})
							if err != nil {
								return nil, err
							}

							return &databroker.GetResponse{
								Record: &databroker.Record{
									Version: "0001",
									Type:    data.GetTypeUrl(),
									Id:      "SESSION_ID",
									Data:    data,
								},
							}, nil
						},
					},
					directoryClient: new(mockDirectoryServiceClient),
				}),
				options:  config.NewAtomicOptions(),
				provider: identity.NewAtomicAuthenticator(),
			}
			a.provider.Store(tt.provider)
			r := httptest.NewRequest("GET", "/", nil)
			state, err := tt.session.LoadSession(r)
			if err != nil {
				t.Fatal(err)
			}
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

			got := a.VerifySession(fn)
			got.ServeHTTP(w, r)
			if status := w.Code; status != tt.wantStatus {
				t.Errorf("VerifySession() error = %v, wantErr %v\n%v\n%v", w.Result().StatusCode, tt.wantStatus, w.Header(), w.Body.String())
			}
		})
	}
}

func TestWellKnownEndpoint(t *testing.T) {
	auth := testAuthenticate()

	h := auth.Handler()
	if h == nil {
		t.Error("handler cannot be nil")
	}
	req := httptest.NewRequest("GET", "/.well-known/pomerium/", nil)
	req.Header.Set("Accept", "application/json")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	body := rr.Body.String()
	expected := "{\"authentication_callback_endpoint\":\"https://auth.example.com/oauth2/callback\",\"jwks_uri\":\"https://auth.example.com/.well-known/pomerium/jwks.json\",\"frontchannel_logout_uri\":\"https://auth.example.com/.pomerium/sign_out\"}\n"
	assert.Equal(t, body, expected)
}

func TestJwksEndpoint(t *testing.T) {
	o := newTestOptions(t)
	o.SigningKey = "LS0tLS1CRUdJTiBFQyBQUklWQVRFIEtFWS0tLS0tCk1IY0NBUUVFSUpCMFZkbko1VjEvbVlpYUlIWHhnd2Q0Yzd5YWRTeXMxb3Y0bzA1b0F3ekdvQW9HQ0NxR1NNNDkKQXdFSG9VUURRZ0FFVUc1eENQMEpUVDFINklvbDhqS3VUSVBWTE0wNENnVzlQbEV5cE5SbVdsb29LRVhSOUhUMwpPYnp6aktZaWN6YjArMUt3VjJmTVRFMTh1dy82MXJVQ0JBPT0KLS0tLS1FTkQgRUMgUFJJVkFURSBLRVktLS0tLQo="
	auth, err := New(&config.Config{Options: o})
	if err != nil {
		t.Fatal(err)
		return
	}
	h := auth.Handler()
	if h == nil {
		t.Error("handler cannot be nil")
	}
	req := httptest.NewRequest("GET", "/.well-known/pomerium/jwks.json", nil)
	req.Header.Set("Accept", "application/json")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	body := rr.Body.String()
	expected := "{\"keys\":[{\"use\":\"sig\",\"kty\":\"EC\",\"kid\":\"5b419ade1895fec2d2def6cd33b1b9a018df60db231dc5ecb85cbed6d942813c\",\"crv\":\"P-256\",\"alg\":\"ES256\",\"x\":\"UG5xCP0JTT1H6Iol8jKuTIPVLM04CgW9PlEypNRmWlo\",\"y\":\"KChF0fR09zm884ymInM29PtSsFdnzExNfLsP-ta1AgQ\"}]}\n"
	assert.Equal(t, expected, body)
}

func TestAuthenticate_userInfo(t *testing.T) {
	t.Parallel()

	now := time.Now()
	pbNow, _ := ptypes.TimestampProto(now)
	tests := []struct {
		name         string
		method       string
		sessionStore sessions.SessionStore
		wantCode     int
		wantBody     string
	}{
		{"good", http.MethodGet, &mstore.Store{Encrypted: true, Session: &sessions.State{ID: "SESSION_ID", IssuedAt: jwt.NewNumericDate(now)}}, http.StatusOK, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			signer, err := jws.NewHS256Signer(nil)
			if err != nil {
				t.Fatal(err)
			}
			a := &Authenticate{
				options: config.NewAtomicOptions(),
				state: newAtomicAuthenticateState(&authenticateState{
					sessionStore:     tt.sessionStore,
					encryptedEncoder: signer,
					sharedEncoder:    signer,
					dataBrokerClient: mockDataBrokerServiceClient{
						get: func(ctx context.Context, in *databroker.GetRequest, opts ...grpc.CallOption) (*databroker.GetResponse, error) {
							data, err := ptypes.MarshalAny(&session.Session{
								Id:      "SESSION_ID",
								UserId:  "USER_ID",
								IdToken: &session.IDToken{IssuedAt: pbNow},
							})
							if err != nil {
								return nil, err
							}

							return &databroker.GetResponse{
								Record: &databroker.Record{
									Version: "0001",
									Type:    data.GetTypeUrl(),
									Id:      "SESSION_ID",
									Data:    data,
								},
							}, nil
						},
					},
					directoryClient: new(mockDirectoryServiceClient),
				}),
				templates: template.Must(frontend.NewTemplates()),
			}
			u, _ := url.Parse("/")
			r := httptest.NewRequest(tt.method, u.String(), nil)
			state, err := tt.sessionStore.LoadSession(r)
			if err != nil {
				t.Fatal(err)
			}
			ctx := r.Context()
			ctx = sessions.NewContext(ctx, state, nil)
			r = r.WithContext(ctx)
			r.Header.Set("Accept", "application/json")

			w := httptest.NewRecorder()
			httputil.HandlerFunc(a.userInfo).ServeHTTP(w, r)
			if status := w.Code; status != tt.wantCode {
				t.Errorf("handler returned wrong status code: got %v want %v", status, tt.wantCode)
			}
			body := w.Body.String()
			if !strings.Contains(body, tt.wantBody) {
				t.Errorf("Unexpected body, contains: %s, got: %s", tt.wantBody, body)
			}
		})
	}
}

type mockDataBrokerServiceClient struct {
	databroker.DataBrokerServiceClient

	delete func(ctx context.Context, in *databroker.DeleteRequest, opts ...grpc.CallOption) (*emptypb.Empty, error)
	get    func(ctx context.Context, in *databroker.GetRequest, opts ...grpc.CallOption) (*databroker.GetResponse, error)
	set    func(ctx context.Context, in *databroker.SetRequest, opts ...grpc.CallOption) (*databroker.SetResponse, error)
}

func (m mockDataBrokerServiceClient) Delete(ctx context.Context, in *databroker.DeleteRequest, opts ...grpc.CallOption) (*emptypb.Empty, error) {
	return m.delete(ctx, in, opts...)
}

func (m mockDataBrokerServiceClient) Get(ctx context.Context, in *databroker.GetRequest, opts ...grpc.CallOption) (*databroker.GetResponse, error) {
	return m.get(ctx, in, opts...)
}

func (m mockDataBrokerServiceClient) Set(ctx context.Context, in *databroker.SetRequest, opts ...grpc.CallOption) (*databroker.SetResponse, error) {
	return m.set(ctx, in, opts...)
}

type mockDirectoryServiceClient struct {
	directory.DirectoryServiceClient

	refreshUser func(ctx context.Context, in *directory.RefreshUserRequest, opts ...grpc.CallOption) (*empty.Empty, error)
}

func (m mockDirectoryServiceClient) RefreshUser(ctx context.Context, in *directory.RefreshUserRequest, opts ...grpc.CallOption) (*empty.Empty, error) {
	if m.refreshUser != nil {
		return m.refreshUser(ctx, in, opts...)
	}
	return nil, status.Error(codes.Unimplemented, "")
}

func TestAuthenticate_SignOut_CSRF(t *testing.T) {
	now := time.Now()
	signer, err := jws.NewHS256Signer(nil)
	if err != nil {
		t.Fatal(err)
	}
	pbNow, _ := ptypes.TimestampProto(now)
	a := &Authenticate{
		options: config.NewAtomicOptions(),
		state: newAtomicAuthenticateState(&authenticateState{
			// sessionStore:     tt.sessionStore,
			cookieSecret:     cryptutil.NewKey(),
			encryptedEncoder: signer,
			sharedEncoder:    signer,
			dataBrokerClient: mockDataBrokerServiceClient{
				get: func(ctx context.Context, in *databroker.GetRequest, opts ...grpc.CallOption) (*databroker.GetResponse, error) {
					data, err := ptypes.MarshalAny(&session.Session{
						Id:      "SESSION_ID",
						UserId:  "USER_ID",
						IdToken: &session.IDToken{IssuedAt: pbNow},
					})
					if err != nil {
						return nil, err
					}

					return &databroker.GetResponse{
						Record: &databroker.Record{
							Version: "0001",
							Type:    data.GetTypeUrl(),
							Id:      "SESSION_ID",
							Data:    data,
						},
					}, nil
				},
			},
			directoryClient: new(mockDirectoryServiceClient),
		}),
		templates: template.Must(frontend.NewTemplates()),
	}
	tests := []struct {
		name          string
		setCSRFCookie bool
		method        string
		wantStatus    int
		wantBody      string
	}{
		{"GET without CSRF should fail", false, "GET", 400, "{\"Status\":400,\"Error\":\"Bad Request: CSRF token invalid\"}\n"},
		{"POST without CSRF should fail", false, "POST", 400, "{\"Status\":400,\"Error\":\"Bad Request: CSRF token invalid\"}\n"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := a.Handler()

			// Obtain a CSRF cookie via a GET request.
			orr, err := http.NewRequest("GET", "/", nil)
			if err != nil {
				t.Fatal(err)
			}
			rr := httptest.NewRecorder()
			s.ServeHTTP(rr, orr)

			r, err := http.NewRequest(tt.method, "/.pomerium/sign_out", nil)
			if err != nil {
				t.Fatal(err)
			}
			if tt.setCSRFCookie {
				r.Header.Set("Cookie", rr.Header().Get("Set-Cookie"))
			}
			r.Header.Set("Accept", "application/json")
			r.Header.Set("Referer", "/")
			rr = httptest.NewRecorder()
			s.ServeHTTP(rr, r)

			if rr.Code != tt.wantStatus {
				t.Errorf("status: got %v want %v", rr.Code, tt.wantStatus)
			}
			body := rr.Body.String()
			if diff := cmp.Diff(body, tt.wantBody); diff != "" {
				t.Errorf("handler returned wrong body Body: %s", diff)
			}
		})
	}
}
