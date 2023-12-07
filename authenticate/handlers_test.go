package authenticate

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v3/jwt"
	"github.com/golang/mock/gomock"
	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/assert"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/oauth2"
	"google.golang.org/grpc"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/atomicutil"
	"github.com/pomerium/pomerium/internal/encoding/jws"
	"github.com/pomerium/pomerium/internal/encoding/mock"
	"github.com/pomerium/pomerium/internal/handlers"
	"github.com/pomerium/pomerium/internal/httputil"
	"github.com/pomerium/pomerium/internal/identity"
	"github.com/pomerium/pomerium/internal/identity/oidc"
	"github.com/pomerium/pomerium/internal/sessions"
	mstore "github.com/pomerium/pomerium/internal/sessions/mock"
	"github.com/pomerium/pomerium/internal/urlutil"
	"github.com/pomerium/pomerium/pkg/cryptutil"
	"github.com/pomerium/pomerium/pkg/grpc/databroker"
)

func testAuthenticate() *Authenticate {
	redirectURL, _ := url.Parse("https://auth.example.com/oauth/callback")
	var auth Authenticate
	auth.state = atomicutil.NewValue(&authenticateState{
		redirectURL:  redirectURL,
		cookieSecret: cryptutil.NewKey(),
		flow:         new(stubFlow),
	})
	auth.options = config.NewAtomicOptions()
	auth.options.Store(&config.Options{
		SharedKey: cryptutil.NewBase64Key(),
	})
	return &auth
}

func TestAuthenticate_RobotsTxt(t *testing.T) {
	auth := testAuthenticate()
	req, err := http.NewRequest(http.MethodGet, "/robots.txt", nil)
	if err != nil {
		t.Fatal(err)
	}
	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(auth.RobotsTxt)
	handler.ServeHTTP(rr, req)
	if status := rr.Code; status != http.StatusOK {
		t.Errorf("handler returned wrong status code: got %v want %v", status, http.StatusOK)
	}
	expected := "User-agent: *\nDisallow: /"
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
	req := httptest.NewRequest(http.MethodGet, "/robots.txt", nil)
	req.Header.Set("Accept", "application/json")

	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	expected := "User-agent: *\nDisallow: /"

	body := rr.Body.String()
	if body != expected {
		t.Errorf("handler returned unexpected body: got %v want %v", body, expected)
	}

	// cors preflight
	req = httptest.NewRequest(http.MethodOptions, "/.pomerium/sign_in", nil)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Access-Control-Request-Method", http.MethodGet)
	req.Header.Set("Access-Control-Request-Headers", "X-Requested-With")
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	expected = "User-agent: *\nDisallow: /"
	code := rr.Code
	if code/100 != 2 {
		t.Errorf("bad preflight code %v", code)
	}
	resp := rr.Result()
	body = resp.Header.Get("vary")
	if body == "" {
		t.Errorf("handler returned unexpected body: got %v want %v", body, expected)
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
		{
			"good post",
			http.MethodPost,
			nil,
			"https://corp.pomerium.io/",
			"",
			"sig",
			"ts",
			identity.MockProvider{GetSignOutURLResponse: "https://microsoft.com"},
			&mstore.Store{Encrypted: true, Session: &sessions.State{}},
			http.StatusFound,
			"",
		},
		{
			"signout redirect url",
			http.MethodPost,
			nil,
			"",
			"https://signout-redirect-url.example.com",
			"sig",
			"ts",
			identity.MockProvider{GetSignOutURLError: oidc.ErrSignoutNotImplemented},
			&mstore.Store{Encrypted: true, Session: &sessions.State{}},
			http.StatusFound,
			"",
		},
		{
			"failed revoke",
			http.MethodPost,
			nil,
			"https://corp.pomerium.io/",
			"",
			"sig",
			"ts",
			identity.MockProvider{GetSignOutURLError: oidc.ErrSignoutNotImplemented, RevokeError: errors.New("OH NO")},
			&mstore.Store{Encrypted: true, Session: &sessions.State{}},
			http.StatusFound,
			"",
		},
		{
			"load session error",
			http.MethodPost,
			errors.New("error"),
			"https://corp.pomerium.io/",
			"",
			"sig",
			"ts",
			identity.MockProvider{GetSignOutURLError: oidc.ErrSignoutNotImplemented, RevokeError: errors.New("OH NO")},
			&mstore.Store{Encrypted: true, Session: &sessions.State{}},
			http.StatusFound,
			"",
		},
		{
			"bad redirect uri",
			http.MethodPost,
			nil,
			"corp.pomerium.io/",
			"",
			"sig",
			"ts",
			identity.MockProvider{GetSignOutURLError: oidc.ErrSignoutNotImplemented},
			&mstore.Store{Encrypted: true, Session: &sessions.State{}},
			http.StatusFound,
			"",
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()
			a := &Authenticate{
				cfg: getAuthenticateConfig(WithGetIdentityProvider(func(options *config.Options, idpID string) (identity.Authenticator, error) {
					return tt.provider, nil
				})),
				state: atomicutil.NewValue(&authenticateState{
					sessionStore:  tt.sessionStore,
					sharedEncoder: mock.Encoder{},
					flow:          new(stubFlow),
				}),
				options: config.NewAtomicOptions(),
			}
			if tt.signoutRedirectURL != "" {
				opts := a.options.Load()
				opts.SignOutRedirectURLString = tt.signoutRedirectURL
				a.options.Store(opts)
			}
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
			httputil.HandlerFunc(a.signOutRedirect).ServeHTTP(w, r)
			if status := w.Code; status != tt.wantCode {
				t.Errorf("handler returned wrong status code: got %v want %v", status, tt.wantCode)
			}
			body := w.Body.String()
			if diff := cmp.Diff(body, tt.wantBody); diff != "" {
				t.Errorf("handler returned wrong body Body: %s", diff)
			}
			if tt.signoutRedirectURL != "" {
				loc := w.Header().Get("Location")
				assert.Contains(t, loc, tt.signoutRedirectURL)
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
		{"too many separators", http.MethodGet, time.Now().Unix(), "", "", "|ok|now|what", "", "code", "https://corp.pomerium.io", "https://authenticate.pomerium.io", &mstore.Store{}, identity.MockProvider{AuthenticateResponse: oauth2.Token{}}, "https://corp.pomerium.io", http.StatusBadRequest},
		{"bad hmac", http.MethodGet, time.Now().Unix(), "", "NOTMAC", "", "", "code", "https://corp.pomerium.io", "https://authenticate.pomerium.io", &mstore.Store{}, identity.MockProvider{AuthenticateResponse: oauth2.Token{}}, "https://corp.pomerium.io", http.StatusBadRequest},
		{"bad hmac", http.MethodGet, time.Now().Unix(), base64.URLEncoding.EncodeToString([]byte("malformed_state")), "", "", "", "code", "https://corp.pomerium.io", "https://authenticate.pomerium.io", &mstore.Store{}, identity.MockProvider{AuthenticateResponse: oauth2.Token{}}, "https://corp.pomerium.io", http.StatusBadRequest},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()
			aead, err := chacha20poly1305.NewX(cryptutil.NewKey())
			if err != nil {
				t.Fatal(err)
			}
			authURL, _ := url.Parse(tt.authenticateURL)
			a := &Authenticate{
				cfg: getAuthenticateConfig(WithGetIdentityProvider(func(options *config.Options, idpID string) (identity.Authenticator, error) {
					return tt.provider, nil
				})),
				state: atomicutil.NewValue(&authenticateState{
					redirectURL:  authURL,
					sessionStore: tt.session,
					cookieCipher: aead,
					flow:         new(stubFlow),
				}),
				options: config.NewAtomicOptions(),
			}
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

	idp, _ := new(config.Options).GetIdentityProviderForID("")

	tests := []struct {
		name    string
		headers map[string]string

		session  sessions.SessionStore
		ctxError error
		provider identity.Authenticator

		wantStatus int
	}{
		{
			"invalid session",
			nil,
			&mstore.Store{Session: &sessions.State{IdentityProviderID: idp.GetId(), ID: "xyz"}},
			errors.New("hi"),
			identity.MockProvider{},
			http.StatusFound,
		},
		{
			"expired,refresh error",
			nil,
			&mstore.Store{Session: &sessions.State{IdentityProviderID: idp.GetId(), ID: "xyz"}},
			sessions.ErrExpired,
			identity.MockProvider{RefreshError: errors.New("error")},
			http.StatusFound,
		},
		{
			"expired,save error",
			nil,
			&mstore.Store{SaveError: errors.New("error"), Session: &sessions.State{IdentityProviderID: idp.GetId(), ID: "xyz"}},
			sessions.ErrExpired,
			identity.MockProvider{RefreshResponse: oauth2.Token{Expiry: time.Now().Add(10 * time.Minute)}},
			http.StatusFound,
		},
		{
			"expired XHR,refresh error",
			map[string]string{"X-Requested-With": "XmlHttpRequest"},
			&mstore.Store{Session: &sessions.State{IdentityProviderID: idp.GetId(), ID: "xyz"}},
			sessions.ErrExpired,
			identity.MockProvider{RefreshError: errors.New("error")},
			http.StatusUnauthorized,
		},
	}
	for _, tt := range tests {
		tt := tt
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
			a := &Authenticate{
				cfg: getAuthenticateConfig(WithGetIdentityProvider(func(options *config.Options, idpID string) (identity.Authenticator, error) {
					return tt.provider, nil
				})),
				state: atomicutil.NewValue(&authenticateState{
					cookieSecret:  cryptutil.NewKey(),
					redirectURL:   uriParseHelper("https://authenticate.corp.beyondperimeter.com"),
					sessionStore:  tt.session,
					cookieCipher:  aead,
					sharedEncoder: signer,
					flow:          new(stubFlow),
				}),
				options: config.NewAtomicOptions(),
			}
			r := httptest.NewRequest(http.MethodGet, "/", nil)
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

func TestAuthenticate_userInfo(t *testing.T) {
	t.Parallel()

	t.Run("cookie-redirect-uri", func(t *testing.T) {
		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodGet, "https://authenticate.service.cluster.local/.pomerium/?pomerium_redirect_uri=https://www.example.com", nil)
		var a Authenticate
		a.state = atomicutil.NewValue(&authenticateState{
			cookieSecret: cryptutil.NewKey(),
			flow:         new(stubFlow),
		})
		a.options = config.NewAtomicOptions()
		a.options.Store(&config.Options{
			SharedKey:                     cryptutil.NewBase64Key(),
			AuthenticateURLString:         "https://authenticate.example.com",
			AuthenticateInternalURLString: "https://authenticate.service.cluster.local",
		})
		err := a.userInfo(w, r)
		assert.NoError(t, err)
		assert.Equal(t, http.StatusFound, w.Code)
		assert.Equal(t, "https://authenticate.example.com/.pomerium/", w.Header().Get("Location"))
	})

	now := time.Now()
	tests := []struct {
		name           string
		url            string
		validSignature bool
		sessionStore   sessions.SessionStore
		wantCode       int
	}{
		{
			"not a redirect",
			"/",
			true,
			&mstore.Store{Encrypted: true, Session: &sessions.State{ID: "SESSION_ID", IssuedAt: jwt.NewNumericDate(now)}},
			http.StatusOK,
		},
		{
			"signed redirect",
			"/?pomerium_redirect_uri=http://example.com",
			true,
			&mstore.Store{Encrypted: true, Session: &sessions.State{ID: "SESSION_ID", IssuedAt: jwt.NewNumericDate(now)}},
			http.StatusFound,
		},
		{
			"invalid redirect",
			"/?pomerium_redirect_uri=http://example.com",
			false,
			&mstore.Store{Encrypted: true, Session: &sessions.State{ID: "SESSION_ID", IssuedAt: jwt.NewNumericDate(now)}},
			http.StatusBadRequest,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			signer, err := jws.NewHS256Signer(nil)
			if err != nil {
				t.Fatal(err)
			}
			o := config.NewAtomicOptions()
			o.Store(&config.Options{
				AuthenticateURLString: "https://authenticate.localhost.pomerium.io",
				SharedKey:             "SHARED KEY",
			})
			f := new(stubFlow)
			if !tt.validSignature {
				f.verifySignatureErr = errors.New("bad signature")
			}
			a := &Authenticate{
				options: o,
				state: atomicutil.NewValue(&authenticateState{
					sessionStore:  tt.sessionStore,
					sharedEncoder: signer,
					flow:          f,
				}),
			}
			r := httptest.NewRequest(http.MethodGet, tt.url, nil)
			state, err := tt.sessionStore.LoadSession(r)
			if err != nil {
				t.Fatal(err)
			}
			ctx := r.Context()
			ctx = sessions.NewContext(ctx, state, nil)
			r = r.WithContext(ctx)
			r.Header.Set("Accept", "application/json")

			w := httptest.NewRecorder()
			a.requireValidSignatureOnRedirect(a.userInfo).ServeHTTP(w, r)
			if status := w.Code; status != tt.wantCode {
				t.Errorf("handler returned wrong status code: got %v want %v", status, tt.wantCode)
			}
		})
	}
}

type mockDataBrokerServiceClient struct {
	databroker.DataBrokerServiceClient

	get func(ctx context.Context, in *databroker.GetRequest, opts ...grpc.CallOption) (*databroker.GetResponse, error)
	put func(ctx context.Context, in *databroker.PutRequest, opts ...grpc.CallOption) (*databroker.PutResponse, error)
}

func (m mockDataBrokerServiceClient) Get(ctx context.Context, in *databroker.GetRequest, opts ...grpc.CallOption) (*databroker.GetResponse, error) {
	return m.get(ctx, in, opts...)
}

func (m mockDataBrokerServiceClient) Put(ctx context.Context, in *databroker.PutRequest, opts ...grpc.CallOption) (*databroker.PutResponse, error) {
	return m.put(ctx, in, opts...)
}

func mustParseURL(rawurl string) *url.URL {
	u, err := url.Parse(rawurl)
	if err != nil {
		panic(err)
	}
	return u
}

// stubFlow is a stub implementation of the flow interface.
type stubFlow struct {
	verifySignatureErr error
}

func (f *stubFlow) VerifyAuthenticateSignature(*http.Request) error {
	return f.verifySignatureErr
}

func (*stubFlow) SignIn(http.ResponseWriter, *http.Request, *sessions.State) error {
	return nil
}

func (*stubFlow) PersistSession(
	context.Context, http.ResponseWriter, *sessions.State, identity.SessionClaims, *oauth2.Token,
) error {
	return nil
}

func (*stubFlow) VerifySession(context.Context, *http.Request, *sessions.State) error {
	return nil
}

func (*stubFlow) RevokeSession(
	context.Context, *http.Request, identity.Authenticator, *sessions.State,
) string {
	return ""
}

func (*stubFlow) GetUserInfoData(*http.Request, *sessions.State) handlers.UserInfoData {
	return handlers.UserInfoData{}
}

func (*stubFlow) LogAuthenticateEvent(*http.Request) {}

func (*stubFlow) GetIdentityProviderIDForURLValues(url.Values) string {
	return ""
}
