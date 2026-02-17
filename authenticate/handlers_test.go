package authenticate

import (
	"context"
	"crypto/cipher"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	oteltrace "go.opentelemetry.io/otel/trace"
	"go.opentelemetry.io/otel/trace/noop"
	"go.uber.org/mock/gomock"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/oauth2"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/handlers"
	"github.com/pomerium/pomerium/internal/httputil"
	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/internal/sessions"
	mstore "github.com/pomerium/pomerium/internal/sessions/mock"
	"github.com/pomerium/pomerium/internal/urlutil"
	"github.com/pomerium/pomerium/pkg/cryptutil"
	configproto "github.com/pomerium/pomerium/pkg/grpc/config"
	"github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/grpc/session"
	"github.com/pomerium/pomerium/pkg/identity"
	"github.com/pomerium/pomerium/pkg/identity/oidc"
	"github.com/pomerium/pomerium/pkg/identity/oidc/hosted"
)

type pkceProvider struct {
	identity.MockProvider
}

func (pkceProvider) PKCEMethods() []string {
	return []string{"S256"}
}

func testAuthenticate(t *testing.T) *Authenticate {
	opts := newTestOptions(t)
	opts.AuthenticateURLString = "https://auth.example.com/oauth/callback"
	auth, err := New(t.Context(), &config.Config{
		Options: opts,
	})
	if err != nil {
		panic(err)
	}
	auth.state.Load().flow = new(stubFlow)
	return auth
}

func TestAuthenticate_RobotsTxt(t *testing.T) {
	t.Parallel()

	auth := testAuthenticate(t)
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
	t.Parallel()

	auth := testAuthenticate(t)

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
		sessionStore sessions.HandleReaderWriter
		wantCode     int
		wantBody     string
		wantLocation string
	}{
		{
			"good post",
			http.MethodPost,
			nil,
			"https://corp.pomerium.io/",
			"",
			"sig",
			"ts",
			identity.MockProvider{SignOutError: oidc.ErrSignoutNotImplemented},
			&mstore.Store{Encrypted: true, SessionHandle: &session.Handle{}},
			http.StatusFound,
			"",
			"https://corp.pomerium.io/",
		},
		{
			"signout redirect url",
			http.MethodPost,
			nil,
			"",
			"https://signout-redirect-url.example.com",
			"sig",
			"ts",
			identity.MockProvider{SignOutError: oidc.ErrSignoutNotImplemented},
			&mstore.Store{Encrypted: true, SessionHandle: &session.Handle{}},
			http.StatusFound,
			"",
			"https://signout-redirect-url.example.com",
		},
		{
			"empty redirect url",
			http.MethodPost,
			nil,
			"",
			"",
			"sig",
			"ts",
			identity.MockProvider{SignOutError: oidc.ErrSignoutNotImplemented},
			&mstore.Store{Encrypted: true, SessionHandle: &session.Handle{}},
			http.StatusFound,
			"",
			"https://authenticate.pomerium.app/.pomerium/signed_out",
		},
		{
			"failed revoke",
			http.MethodPost,
			nil,
			"https://corp.pomerium.io/",
			"",
			"sig",
			"ts",
			identity.MockProvider{SignOutError: oidc.ErrSignoutNotImplemented, RevokeError: errors.New("OH NO")},
			&mstore.Store{Encrypted: true, SessionHandle: &session.Handle{}},
			http.StatusFound,
			"",
			"https://corp.pomerium.io/",
		},
		{
			"load session error",
			http.MethodPost,
			errors.New("error"),
			"https://corp.pomerium.io/",
			"",
			"sig",
			"ts",
			identity.MockProvider{SignOutError: oidc.ErrSignoutNotImplemented, RevokeError: errors.New("OH NO")},
			&mstore.Store{Encrypted: true, SessionHandle: &session.Handle{}},
			http.StatusFound,
			"",
			"https://corp.pomerium.io/",
		},
		{
			"bad redirect uri",
			http.MethodPost,
			nil,
			"corp.pomerium.io/",
			"",
			"sig",
			"ts",
			identity.MockProvider{SignOutError: oidc.ErrSignoutNotImplemented},
			&mstore.Store{Encrypted: true, SessionHandle: &session.Handle{}},
			http.StatusFound,
			"",
			"/corp.pomerium.io/",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			ctrl := gomock.NewController(t)
			defer ctrl.Finish()
			a := testAuthenticate(t)
			a.cfg = getAuthenticateConfig(WithGetIdentityProvider(func(_ context.Context, _ oteltrace.TracerProvider, _ *config.Options, _ string) (identity.Authenticator, error) {
				return tt.provider, nil
			}))
			a.state.Store(&authenticateState{
				sessionHandleReader: tt.sessionStore,
				sessionHandleWriter: tt.sessionStore,
				flow:                new(stubFlow),
			})
			a.options.Store(new(config.Options))
			if tt.signoutRedirectURL != "" {
				opts := a.options.Load()
				opts.SignOutRedirectURLString = tt.signoutRedirectURL
				a.options.Store(opts)
			}
			u, _ := url.Parse("/sign_out")
			params, _ := url.ParseQuery(u.RawQuery)
			params.Add("sig", tt.sig)
			params.Add("ts", tt.ts)
			if tt.redirectURL != "" {
				params.Add(urlutil.QueryRedirectURI, tt.redirectURL)
			}
			u.RawQuery = params.Encode()
			r := httptest.NewRequest(tt.method, u.String(), nil)
			r.Header.Set("Accept", "application/json")

			w := httptest.NewRecorder()
			httputil.HandlerFunc(a.signOutAndRedirect).ServeHTTP(w, r)
			if status := w.Code; status != tt.wantCode {
				t.Errorf("handler returned wrong status code: got %v want %v", status, tt.wantCode)
			}
			body := w.Body.String()
			if diff := cmp.Diff(body, tt.wantBody); diff != "" {
				t.Errorf("handler returned wrong body Body: %s", diff)
			}
			loc := w.Header().Get("Location")
			assert.Equal(t, tt.wantLocation, loc)
		})
	}
}

func TestAuthenticate_SignOutDoesNotRequireSession(t *testing.T) {
	t.Parallel()

	// A direct sign_out request would not be signed.
	f := new(stubFlow)
	f.verifySignatureErr = errors.New("no signature")

	sessionStore := &mstore.Store{LoadError: errors.New("no session")}
	a := &Authenticate{
		cfg: getAuthenticateConfig(WithGetIdentityProvider(func(_ context.Context, _ oteltrace.TracerProvider, _ *config.Options, _ string) (identity.Authenticator, error) {
			return identity.MockProvider{}, nil
		})),
	}
	a.state.Store(&authenticateState{
		sessionHandleWriter: sessionStore,
		flow:                f,
	})
	a.options.Store(new(config.Options))
	r := httptest.NewRequest(http.MethodGet, "/.pomerium/sign_out", nil)
	w := httptest.NewRecorder()

	a.Handler().ServeHTTP(w, r)
	result := w.Result()

	// The handler should serve a sign out confirmation page, not a login redirect.
	expectedStatus := "200 OK"
	if result.Status != expectedStatus {
		t.Fatalf("wrong status code: got %q want %q", result.Status, expectedStatus)
	}
	body, _ := io.ReadAll(result.Body)
	assert.Contains(t, string(body), `"page":"SignOutConfirm"`)
}

func TestAuthenticate_SignOutNoConfirmationForHosted(t *testing.T) {
	t.Parallel()

	// A direct sign_out request would not be signed.
	f := new(stubFlow)
	f.verifySignatureErr = errors.New("no signature")

	sessionStore := &mstore.Store{LoadError: errors.New("no session")}
	tracerProvider := noop.NewTracerProvider()
	tracer := tracerProvider.Tracer("test")
	mockIDP := identity.MockProvider{
		SignOutError: errors.New("returning an error here to trigger a signed_out redirect"),
	}
	a := &Authenticate{
		cfg: getAuthenticateConfig(WithGetIdentityProvider(func(_ context.Context, _ oteltrace.TracerProvider, _ *config.Options, _ string) (identity.Authenticator, error) {
			return &mockIDP, nil
		})),
		tracerProvider: tracerProvider,
		tracer:         tracer,
	}
	a.state.Store(&authenticateState{
		sessionHandleReader: sessionStore,
		sessionHandleWriter: sessionStore,
		flow:                f,
	})
	opts := config.Options{
		Provider: hosted.Name,
	}
	a.options.Store(&opts)
	r := httptest.NewRequest(http.MethodGet, "/.pomerium/sign_out", nil)
	w := httptest.NewRecorder()

	a.Handler().ServeHTTP(w, r)
	result := w.Result()

	// The handler should not serve a sign out confirmation page.
	expectedStatus := "302 Found"
	if result.Status != expectedStatus {
		t.Fatalf("wrong status code: got %q want %q", result.Status, expectedStatus)
	}
	assert.Equal(t, "https://authenticate.pomerium.app/.pomerium/signed_out", result.Header.Get("Location"))
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
		session         sessions.HandleWriter
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
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			ctrl := gomock.NewController(t)
			defer ctrl.Finish()
			aead, err := chacha20poly1305.NewX(cryptutil.NewKey())
			if err != nil {
				t.Fatal(err)
			}
			authURL, _ := url.Parse(tt.authenticateURL)
			a := testAuthenticate(t)
			a.cfg = getAuthenticateConfig(WithGetIdentityProvider(func(_ context.Context, _ oteltrace.TracerProvider, _ *config.Options, _ string) (identity.Authenticator, error) {
				return tt.provider, nil
			}))
			csrf := newCSRFCookieValidation(cryptutil.NewKey(), "_csrf", http.SameSiteLaxMode)
			a.state.Store(&authenticateState{
				redirectURL:         authURL,
				sessionHandleWriter: tt.session,
				cookieCipher:        aead,
				csrf:                csrf,
				flow:                new(stubFlow),
			})
			a.options.Store(new(config.Options))
			u, _ := url.Parse("/oauthGet")
			params, _ := url.ParseQuery(u.RawQuery)
			params.Add("error", tt.paramErr)
			params.Add("code", tt.code)
			csrfCookie, token := getCSRFCookieAndTokenForTest(t, csrf)
			encodedState := testOAuthState{
				Token:       token,
				Timestamp:   tt.ts,
				ExtraMac:    tt.extraMac,
				RedirectURI: tt.redirectURI,
			}.Encode(a.state.Load().cookieCipher)
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
			r.AddCookie(csrfCookie)
			w := httptest.NewRecorder()
			httputil.HandlerFunc(a.OAuthCallback).ServeHTTP(w, r)
			if w.Result().StatusCode != tt.wantCode {
				t.Errorf("Authenticate.OAuthCallback() error = %v, wantErr %v\n%v", w.Result().StatusCode, tt.wantCode, w.Body.String())
				return
			}
		})
	}
}

type testOAuthState struct {
	Token       string
	Timestamp   int64
	ExtraMac    string
	RedirectURI string
}

func (s testOAuthState) Encode(cc cipher.AEAD) string {
	// (token|timestamp|trace_id+flags|encrypt(redirect_url),mac(token|timestamp|trace_id+flags|))
	b := []byte(fmt.Sprintf("%s|%d||%s", s.Token, s.Timestamp, s.ExtraMac))
	enc := cryptutil.Encrypt(cc, []byte(s.RedirectURI), b)
	b = append(b, enc...)
	return base64.URLEncoding.EncodeToString(b)
}

func TestAuthenticate_OAuthCallback_CSRF(t *testing.T) {
	t.Parallel()

	aead, err := chacha20poly1305.NewX(cryptutil.NewKey())
	require.NoError(t, err)
	authURL, _ := url.Parse("https://authenticate.pomerium.io")
	a := testAuthenticate(t)
	a.cfg = getAuthenticateConfig(WithGetIdentityProvider(func(_ context.Context, _ oteltrace.TracerProvider, _ *config.Options, _ string) (identity.Authenticator, error) {
		return identity.MockProvider{AuthenticateResponse: oauth2.Token{}}, nil
	}))
	csrf := newCSRFCookieValidation(cryptutil.NewKey(), "_csrf", http.SameSiteLaxMode)
	a.state.Store(&authenticateState{
		redirectURL:         authURL,
		sessionHandleWriter: &mstore.Store{},
		cookieCipher:        aead,
		csrf:                csrf,
		flow:                new(stubFlow),
	})
	a.options.Store(new(config.Options))

	csrfCookie, token := getCSRFCookieAndTokenForTest(t, csrf)

	newReq := func(cookie *http.Cookie, token string) *http.Request {
		encodedState := testOAuthState{
			Token:       token,
			Timestamp:   time.Now().Unix(),
			RedirectURI: "https://corp.pomerium.io",
		}.Encode(aead)
		u, _ := url.Parse("/oauthGet")
		u.RawQuery = url.Values{
			"code":  []string{"code"},
			"state": []string{encodedState},
		}.Encode()
		r := httptest.NewRequest(http.MethodGet, u.String(), nil)
		if cookie != nil {
			r.AddCookie(cookie)
		}
		return r
	}

	// Set up a few mismatched/invalid values too.
	otherCookie, otherToken := getCSRFCookieAndTokenForTest(t, csrf)
	invalidCookie := *otherCookie
	invalidCookie.Value = "invalid-cookie-format"

	cases := []struct {
		name           string
		cookie         *http.Cookie
		token          string
		expectedStatus int
	}{
		{"ok", csrfCookie, token, http.StatusFound},
		{"no cookie", nil, token, http.StatusBadRequest},
		{"mismatched cookie", otherCookie, token, http.StatusBadRequest},
		{"invalid cookie", &invalidCookie, token, http.StatusBadRequest},
		{"empty token", csrfCookie, "", http.StatusBadRequest},
		{"mismatched token", csrfCookie, otherToken, http.StatusBadRequest},
		{"invalid token", &invalidCookie, "not-a-valid-token", http.StatusBadRequest},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()

			r := newReq(c.cookie, c.token)
			w := httptest.NewRecorder()

			httputil.HandlerFunc(a.OAuthCallback).ServeHTTP(w, r)

			result := w.Result()
			assert.Equal(t, c.expectedStatus, result.StatusCode)
		})
	}
}

func TestAuthenticate_OAuthCallback_PKCERequiredMissing(t *testing.T) {
	t.Parallel()

	aead, err := chacha20poly1305.NewX(cryptutil.NewKey())
	require.NoError(t, err)
	authURL, _ := url.Parse("https://authenticate.pomerium.io")
	opts := newTestOptions(t)
	cookieSecret, err := opts.GetCookieSecret()
	require.NoError(t, err)
	csrf := newCSRFCookieValidation(cryptutil.NewKey(), "_csrf", http.SameSiteLaxMode)

	a := testAuthenticate(t)
	a.cfg = getAuthenticateConfig(WithGetIdentityProvider(func(_ context.Context, _ oteltrace.TracerProvider, _ *config.Options, _ string) (identity.Authenticator, error) {
		return pkceProvider{MockProvider: identity.MockProvider{AuthenticateResponse: oauth2.Token{}}}, nil
	}))
	a.state.Store(&authenticateState{
		redirectURL:         authURL,
		sessionHandleWriter: &mstore.Store{},
		cookieCipher:        aead,
		csrf:                csrf,
		pkceStore:           newPKCEStore(opts, aead, cookieSecret),
		flow:                new(stubFlow),
	})
	a.options.Store(opts)

	csrfCookie, token := getCSRFCookieAndTokenForTest(t, csrf)
	encodedState := testOAuthState{
		Token:       token,
		Timestamp:   time.Now().Unix(),
		RedirectURI: "https://corp.pomerium.io",
	}.Encode(aead)
	u, _ := url.Parse("/oauthGet")
	u.RawQuery = url.Values{
		"code":  []string{"code"},
		"state": []string{encodedState},
	}.Encode()

	r := httptest.NewRequest(http.MethodGet, u.String(), nil)
	r.AddCookie(csrfCookie)
	w := httptest.NewRecorder()
	httputil.HandlerFunc(a.OAuthCallback).ServeHTTP(w, r)
	assert.Equal(t, http.StatusBadRequest, w.Result().StatusCode)
}

func TestAuthenticate_SessionValidatorMiddleware(t *testing.T) {
	t.Parallel()
	fn := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		fmt.Fprintln(w, "RVSI FILIVS CAISAR")
		w.WriteHeader(http.StatusOK)
	})

	idp, _ := new(config.Options).GetIdentityProviderForID("")

	tests := []struct {
		name    string
		headers map[string]string

		session  sessions.HandleReaderWriter
		ctxError error
		provider identity.Authenticator

		wantStatus int
	}{
		{
			"invalid session",
			nil,
			&mstore.Store{SessionHandle: &session.Handle{IdentityProviderId: idp.GetId(), Id: "xyz"}},
			errors.New("hi"),
			identity.MockProvider{},
			http.StatusOK,
		},
		{
			"expired,refresh error",
			nil,
			&mstore.Store{SessionHandle: &session.Handle{IdentityProviderId: idp.GetId(), Id: "xyz"}},
			sessions.ErrExpired,
			identity.MockProvider{RefreshError: errors.New("error")},
			http.StatusOK,
		},
		{
			"expired,save error",
			nil,
			&mstore.Store{SaveError: errors.New("error"), SessionHandle: &session.Handle{IdentityProviderId: idp.GetId(), Id: "xyz"}},
			sessions.ErrExpired,
			identity.MockProvider{RefreshResponse: oauth2.Token{Expiry: time.Now().Add(10 * time.Minute)}},
			http.StatusOK,
		},
		{
			"expired XHR,refresh error",
			map[string]string{"X-Requested-With": "XmlHttpRequest"},
			&mstore.Store{SessionHandle: &session.Handle{IdentityProviderId: idp.GetId(), Id: "xyz"}},
			sessions.ErrExpired,
			identity.MockProvider{RefreshError: errors.New("error")},
			http.StatusUnauthorized,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			aead, err := chacha20poly1305.NewX(cryptutil.NewKey())
			if err != nil {
				t.Fatal(err)
			}
			a := testAuthenticate(t)
			a.cfg = getAuthenticateConfig(WithGetIdentityProvider(func(_ context.Context, _ oteltrace.TracerProvider, _ *config.Options, _ string) (identity.Authenticator, error) {
				return tt.provider, nil
			}))
			a.state.Store(&authenticateState{
				redirectURL:         uriParseHelper("https://authenticate.corp.beyondperimeter.com"),
				sessionHandleReader: tt.session,
				sessionHandleWriter: tt.session,
				cookieCipher:        aead,
				flow:                new(stubFlow),
				csrf:                newCSRFCookieValidation(cryptutil.NewKey(), "_csrf", http.SameSiteLaxMode),
			})
			a.options.Store(new(config.Options))
			r := httptest.NewRequest(http.MethodGet, "/", nil)

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
		a := testAuthenticate(t)
		a.state.Store(&authenticateState{
			flow: new(stubFlow),
		})
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
		sessionStore   sessions.HandleReaderWriter
		wantCode       int
	}{
		{
			"not a redirect",
			"/",
			true,
			&mstore.Store{Encrypted: true, SessionHandle: &session.Handle{Id: "SESSION_ID", Iat: timestamppb.New(now)}},
			http.StatusOK,
		},
		{
			"signed redirect",
			"/?pomerium_redirect_uri=http://example.com",
			true,
			&mstore.Store{Encrypted: true, SessionHandle: &session.Handle{Id: "SESSION_ID", Iat: timestamppb.New(now)}},
			http.StatusFound,
		},
		{
			"invalid redirect",
			"/?pomerium_redirect_uri=http://example.com",
			false,
			&mstore.Store{Encrypted: true, SessionHandle: &session.Handle{Id: "SESSION_ID", Iat: timestamppb.New(now)}},
			http.StatusBadRequest,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			f := new(stubFlow)
			if !tt.validSignature {
				f.verifySignatureErr = errors.New("bad signature")
			}
			a := testAuthenticate(t)
			a.state.Store(&authenticateState{
				sessionHandleReader: tt.sessionStore,
				sessionHandleWriter: tt.sessionStore,
				flow:                f,
			})
			a.options.Store(&config.Options{
				AuthenticateURLString: "https://authenticate.localhost.pomerium.io",
				SharedKey:             "SHARED KEY",
			})
			r := httptest.NewRequest(http.MethodGet, tt.url, nil)
			r.Header.Set("Accept", "application/json")

			w := httptest.NewRecorder()
			a.requireValidSignatureOnRedirect(a.userInfo).ServeHTTP(w, r)
			if status := w.Code; status != tt.wantCode {
				t.Errorf("handler returned wrong status code: got %v want %v", status, tt.wantCode)
			}
		})
	}
}

func TestAuthenticate_CORS(t *testing.T) {
	t.Parallel()

	t.Run("unsigned", func(t *testing.T) {
		t.Parallel()

		f := new(stubFlow)
		auth := testAuthenticate(t)
		state := auth.state.Load()
		state.sessionHandleReader = &mstore.Store{SessionHandle: &session.Handle{}}
		state.sessionHandleWriter = &mstore.Store{SessionHandle: &session.Handle{}}
		state.flow = f
		auth.state.Store(state)

		f.verifySignatureErr = errors.New("no signature")

		rr := httptest.NewRecorder()
		logOutput := log.CaptureOutput(t.Context(), func(ctx context.Context) {
			req := httptest.NewRequestWithContext(ctx, http.MethodGet, "/.pomerium/", nil)
			req.Header.Set("Origin", "foo.example.com")
			auth.Handler().ServeHTTP(rr, req)
		})
		assert.NotContains(t, logOutput, "authenticate: signed URL")
		h := rr.Result().Header
		assert.Empty(t, h.Get("Access-Control-Allow-Credentials"))
		assert.Empty(t, h.Get("Access-Control-Allow-Origin"))
	})
	t.Run("signed", func(t *testing.T) {
		t.Parallel()

		f := new(stubFlow)
		auth := testAuthenticate(t)
		state := auth.state.Load()
		state.sessionHandleReader = &mstore.Store{SessionHandle: &session.Handle{}}
		state.sessionHandleWriter = &mstore.Store{SessionHandle: &session.Handle{}}
		state.flow = f
		auth.state.Store(state)

		f.verifySignatureErr = nil
		rr := httptest.NewRecorder()
		logOutput := log.CaptureOutput(t.Context(), func(ctx context.Context) {
			req := httptest.NewRequestWithContext(ctx, http.MethodGet, "/.pomerium/", nil)
			req.Header.Set("Origin", "foo.example.com")
			auth.Handler().ServeHTTP(rr, req)
		})
		assert.Contains(t, logOutput,
			`{"level":"info","message":"authenticate: signed URL, adding CORS headers"}`)
		h := rr.Result().Header
		assert.Equal(t, "true", h.Get("Access-Control-Allow-Credentials"))
		assert.Equal(t, "foo.example.com", h.Get("Access-Control-Allow-Origin"))
	})
}

func TestSignOutBranding(t *testing.T) {
	t.Parallel()

	auth := testAuthenticate(t)
	auth.state.Load().flow.(*stubFlow).verifySignatureErr = errors.New("unsigned URL")
	auth.options.Store(&config.Options{
		BrandingOptions: &configproto.Settings{
			PrimaryColor:   proto.String("red"),
			SecondaryColor: proto.String("orange"),
		},
	})

	t.Run("sign_out", func(t *testing.T) {
		t.Parallel()

		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodGet, "/.pomerium/sign_out", nil)
		err := auth.SignOut(w, r)
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, w.Code)

		b, err := io.ReadAll(w.Body)
		require.NoError(t, err)

		assert.Contains(t, string(b), `"primaryColor":"red","secondaryColor":"orange"`)
	})

	t.Run("signed_out", func(t *testing.T) {
		t.Parallel()

		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodGet, "/.pomerium/signed_out", nil)
		err := auth.signedOut(w, r)
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, w.Code)

		b, err := io.ReadAll(w.Body)
		require.NoError(t, err)

		assert.Contains(t, string(b), `"primaryColor":"red","secondaryColor":"orange"`)
	})
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

// stubFlow is a stub implementation of the flow interface.
type stubFlow struct {
	verifySignatureErr error
}

var _ flow = (*stubFlow)(nil)

func (f *stubFlow) GetIdentityProviderIDForURLValues(url.Values) string {
	return ""
}

func (f *stubFlow) AuthenticatePendingSession(_ http.ResponseWriter, _ *http.Request, _ *session.Handle) error {
	return nil
}

func (f *stubFlow) GetSessionBindingInfo(_ http.ResponseWriter, _ *http.Request, _ *session.Handle) error {
	return nil
}

func (f *stubFlow) RevokeSessionBinding(_ http.ResponseWriter, _ *http.Request, _ *session.Handle) error {
	return nil
}

func (f *stubFlow) RevokeIdentityBinding(_ http.ResponseWriter, _ *http.Request, _ *session.Handle) error {
	return nil
}

func (f *stubFlow) VerifyAuthenticateSignature(*http.Request) error {
	return f.verifySignatureErr
}

func (*stubFlow) SignIn(http.ResponseWriter, *http.Request, *session.Handle) error {
	return nil
}

func (*stubFlow) PersistSession(
	context.Context, http.ResponseWriter, *session.Handle, identity.SessionClaims, *oauth2.Token,
) error {
	return nil
}

func (*stubFlow) VerifySession(context.Context, *http.Request, *session.Handle) error {
	return nil
}

func (*stubFlow) RevokeSession(
	context.Context, *http.Request, identity.Authenticator, *session.Handle,
) string {
	return ""
}

func (*stubFlow) GetUserInfoData(*http.Request, *session.Handle) handlers.UserInfoData {
	return handlers.UserInfoData{}
}

func (*stubFlow) LogAuthenticateEvent(*http.Request) {}
