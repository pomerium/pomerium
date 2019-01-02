//todo(bdd) : refactor sign-in and sign-out tests
package authenticate

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/pomerium/pomerium/authenticate/providers"
	"github.com/pomerium/pomerium/internal/aead"
	"github.com/pomerium/pomerium/internal/httputil"
	"github.com/pomerium/pomerium/internal/sessions"
	"github.com/pomerium/pomerium/internal/testutil"
)

func init() {
	log.SetFlags(log.Ldate | log.Ltime | log.Lshortfile)
}

func testOptions() *Options {
	o := defaultOptions
	o.CookieSecret = "foobar"
	o.ClientID = "bazquux"
	o.ClientSecret = "xyzzyplugh"
	o.EmailDomains = []string{"*"}
	o.ProxyClientID = "abcdef"
	o.ProxyClientSecret = "testtest"
	o.ProxyRootDomains = []string{"*"}
	o.Host = "/"
	o.CookieRefresh = time.Hour
	o.CookieSecret = testEncodedCookieSecret
	o.RedirectURL, _ = url.Parse("https://1.1.1.1/oauth2/callback")
	o.ProviderURL, _ = url.Parse("https://1.1.1.1/")

	return o
}

func errorMsg(msgs []string) string {
	result := make([]string, 0)
	result = append(result, "Invalid configuration:")
	result = append(result, msgs...)
	return strings.Join(result, "\n  ")
}

func TestInitializedOptions(t *testing.T) {
	o := testOptions()
	testutil.Equal(t, nil, o.Validate())
}

// Note that it's not worth testing nonparseable URLs, since url.Parse()
// seems to parse damn near anything.
func TestRedirectURL(t *testing.T) {
	o := testOptions()
	redirectURL, _ := url.Parse("https://myhost.com/oauth2/callback")
	o.RedirectURL = redirectURL
	testutil.Equal(t, nil, o.Validate())
	expected := &url.URL{Scheme: "https", Host: "myhost.com", Path: "/oauth2/callback"}
	testutil.Equal(t, expected, o.RedirectURL)
}

func TestCookieRefreshMustBeLessThanCookieExpire(t *testing.T) {
	o := testOptions()
	testutil.Equal(t, nil, o.Validate())

	o.CookieSecret = testEncodedCookieSecret
	o.CookieRefresh = o.CookieExpire
	testutil.NotEqual(t, nil, o.Validate())

	o.CookieRefresh -= time.Duration(1)
	testutil.Equal(t, nil, o.Validate())
}

func TestBase64CookieSecret(t *testing.T) {
	o := testOptions()
	testutil.Equal(t, nil, o.Validate())

	// 32 byte, base64 (urlsafe) encoded key
	o.CookieSecret = testEncodedCookieSecret
	testutil.Equal(t, nil, o.Validate())

	// 32 byte, base64 (urlsafe) encoded key, w/o padding
	o.CookieSecret = testEncodedCookieSecret
	testutil.Equal(t, nil, o.Validate())
}

func TestValidateCookie(t *testing.T) {
	o := testOptions()
	o.CookieName = "_valid_cookie_name"
	testutil.Equal(t, nil, o.Validate())
}

func setMockCSRFStore(store *sessions.MockCSRFStore) func(*Authenticator) error {
	return func(a *Authenticator) error {
		a.csrfStore = store
		return nil
	}
}

func setMockSessionStore(store *sessions.MockSessionStore) func(*Authenticator) error {
	return func(a *Authenticator) error {
		a.sessionStore = store
		return nil
	}
}

func setMockAuthCodeCipher(cipher *aead.MockCipher, s interface{}) func(*Authenticator) error {
	marshaled, _ := json.Marshal(s)
	if len(marshaled) > 0 && cipher != nil {
		cipher.UnmarshalBytes = marshaled
	}
	return func(a *Authenticator) error {
		a.cipher = cipher
		return nil
	}
}

func setTestProvider(provider *providers.TestProvider) func(*Authenticator) error {
	return func(a *Authenticator) error {
		a.provider = provider
		return nil
	}
}

// generated using `openssl rand 32 -base64`
var testEncodedCookieSecret = "x7xzsM1Ky4vGQPwqy6uTztfr3jtm/pIdRbJXgE0q8kU="
var testAuthCodeSecret = "qICChm3wdjbjcWymm7PefwtPP6/PZv+udkFEubTeE38="

func testOpts(proxyClientID, proxyClientSecret string) *Options {
	opts := defaultOptions
	opts.ProxyClientID = proxyClientID
	opts.ProxyClientSecret = proxyClientSecret
	opts.CookieSecret = testEncodedCookieSecret
	opts.ClientID = "bazquux"
	opts.ClientSecret = "xyzzyplugh"
	opts.AuthCodeSecret = testAuthCodeSecret
	opts.ProxyRootDomains = []string{"example.com"}
	opts.EmailDomains = []string{"example.com"}

	opts.Host = "/"
	opts.RedirectURL, _ = url.Parse("https://1.1.1.1/oauth2/callback")
	opts.ProviderURL, _ = url.Parse("https://1.1.1.1/")

	return opts
}

func newRevokeServer(accessToken string) (*url.URL, *httptest.Server) {
	s := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		token := r.Form.Get("token")

		if token == accessToken {
			rw.WriteHeader(http.StatusOK)
		} else {
			rw.WriteHeader(http.StatusBadRequest)
		}
	}))
	u, _ := url.Parse(s.URL)
	return u, s
}

func TestRobotsTxt(t *testing.T) {
	opts := testOpts("abced", "testtest")
	// opts.Validate()
	proxy, err := NewAuthenticator(opts, func(p *Authenticator) error {
		p.Validator = func(string) bool { return true }
		return nil
	})
	testutil.Ok(t, err)
	rw := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/robots.txt", nil)
	proxy.Handler().ServeHTTP(rw, req)
	if rw.Code != http.StatusOK {
		t.Errorf("expected status code %d, but got %d", http.StatusOK, rw.Code)
	}
	if rw.Body.String() != "User-agent: *\nDisallow: /" {
		t.Errorf("expected response body to be %s but was %s", "User-agent: *\nDisallow: /", rw.Body.String())
	}
}

const redirectInputPattern = `<input type="hidden" name="redirect_uri" value="([^"]+)">`
const revokeErrorMessagePattern = `An error occurred during sign out\. Please try again\.`

type providerRefreshResponse struct {
	OK    bool
	Error error
}

type errResponse struct {
	Error string
}

func TestGetAuthCodeRedirectURL(t *testing.T) {
	testCases := []struct {
		name        string
		redirectURI string
		expectedURI string
	}{
		{
			name:        "url scheme included",
			redirectURI: "http://example.com",
			expectedURI: "http://example.com?code=code&state=state",
		},
		{
			name:        "url scheme not included",
			redirectURI: "example.com",
			expectedURI: "https://example.com?code=code&state=state",
		},
		{
			name:        "auth code is overwritten",
			redirectURI: "http://example.com?code=different",
			expectedURI: "http://example.com?code=code&state=state",
		},
		{
			name:        "state is overwritten",
			redirectURI: "https://example.com?state=different",
			expectedURI: "https://example.com?code=code&state=state",
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {

			redirectURL, err := url.Parse(tc.redirectURI)
			rString := redirectURL.String()
			if err != nil {
				t.Fatalf("error parsing redirect uri %s", err.Error())
			}
			uri := getAuthCodeRedirectURL(redirectURL, "state", "code")
			if uri != tc.expectedURI {
				t.Errorf("expected redirect uri to be %s but was %s", tc.expectedURI, uri)
			}

			if redirectURL.String() != rString {
				t.Errorf("expected original redirect url to be unchanged - expected %s but got %s", redirectURL.String(), rString)
			}

		})
	}
}

func TestProxyOAuthRedirect(t *testing.T) {
	testCases := []struct {
		name               string
		paramsMap          map[string]string
		mockCipher         *aead.MockCipher
		expectedStatusCode int
	}{
		{
			name: "successful case",
			paramsMap: map[string]string{
				"state":        "state",
				"redirect_uri": "http://example.com",
			},
			mockCipher: &aead.MockCipher{
				MarshalString: "abced",
			},
			expectedStatusCode: http.StatusFound,
		},
		{
			name:               "empty state",
			expectedStatusCode: http.StatusForbidden,
		},
		{
			name: "empty redirect uri",
			paramsMap: map[string]string{
				"state": "state",
			},
			expectedStatusCode: http.StatusForbidden,
		},
		{
			name: "malformed redirect uri",
			paramsMap: map[string]string{
				"state":        "state",
				"redirect_uri": ":",
			},
			expectedStatusCode: http.StatusBadRequest,
		},
		{
			name: "save session error",
			paramsMap: map[string]string{
				"state":        "state",
				"redirect_uri": "http://example.com",
			},
			mockCipher:         &aead.MockCipher{MarshalError: fmt.Errorf("error")},
			expectedStatusCode: http.StatusInternalServerError,
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			now := time.Now()

			opts := testOpts("clientId", "clientSecret")
			opts.Validate()

			proxy, _ := NewAuthenticator(opts, setMockAuthCodeCipher(tc.mockCipher, nil))
			params := url.Values{}
			for paramKey, val := range tc.paramsMap {
				params.Set(paramKey, val)
			}
			req := httptest.NewRequest("POST", "/", bytes.NewBufferString(params.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			rw := httptest.NewRecorder()
			sessionState := &sessions.SessionState{
				AccessToken:     "accessToken",
				RefreshDeadline: now.Add(time.Hour),
				RefreshToken:    "refreshToken",
				Email:           "emailaddress",
			}
			proxy.ProxyOAuthRedirect(rw, req, sessionState)
			if rw.Code != tc.expectedStatusCode {
				t.Errorf("expected status to be %d but was %d", tc.expectedStatusCode, rw.Code)
			}

		})
	}
}

type testRefreshProvider struct {
	*providers.ProviderData
	refreshFunc func(string) (string, time.Duration, error)
}

func (trp *testRefreshProvider) RefreshAccessToken(a string) (string, time.Duration, error) {
	return trp.refreshFunc(a)
}

func TestRefreshEndpoint(t *testing.T) {
	type refreshResponse struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		ExpiresIn    int64  `json:"expires_in"`
		Email        string `json:"email"`
	}
	testCases := []struct {
		name                string
		refreshToken        string
		refreshFunc         func(string) (string, time.Duration, error)
		expectedStatusCode  int
		expectedRefreshResp *refreshResponse
	}{
		{
			name:               "no refresh token in request",
			refreshToken:       "",
			expectedStatusCode: http.StatusBadRequest,
		},
		{
			name:               "successful return new access token",
			refreshToken:       "refresh",
			refreshFunc:        func(a string) (string, time.Duration, error) { return "access", 1 * time.Hour, nil },
			expectedStatusCode: http.StatusCreated,
			expectedRefreshResp: &refreshResponse{
				AccessToken: "access",
				ExpiresIn:   int64((1 * time.Hour).Seconds()),
			},
		},
		{
			name:               "returns correct seconds value",
			refreshToken:       "refresh",
			refreshFunc:        func(a string) (string, time.Duration, error) { return "access", 367 * time.Second, nil },
			expectedStatusCode: http.StatusCreated,
			expectedRefreshResp: &refreshResponse{
				AccessToken: "access",
				ExpiresIn:   367,
			},
		},
		{
			name:               "error calling upstream provider with refresh token",
			refreshToken:       "refresh",
			refreshFunc:        func(a string) (string, time.Duration, error) { return "", 0, fmt.Errorf("upstream error") },
			expectedStatusCode: http.StatusInternalServerError,
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			opts := testOpts("client_id", "client_secret")
			opts.Validate()

			p, _ := NewAuthenticator(opts)
			p.provider = &testRefreshProvider{refreshFunc: tc.refreshFunc}
			params := url.Values{}
			params.Set("refresh_token", tc.refreshToken)
			req := httptest.NewRequest("POST", "/", bytes.NewBufferString(params.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			req.Header.Set("Accept", "application/json")
			rw := httptest.NewRecorder()
			p.Refresh(rw, req)
			resp := rw.Result()
			if resp.StatusCode != tc.expectedStatusCode {
				t.Errorf("expected status code to be %d but was %d", tc.expectedStatusCode, rw.Code)
				return
			}

			respBytes, err := ioutil.ReadAll(resp.Body)
			if err != nil {
				t.Fatalf("error reading response body: %s", err.Error())
			}
			if resp.StatusCode == http.StatusOK {
				refreshResp := &refreshResponse{}
				err = json.Unmarshal(respBytes, refreshResp)
				if err != nil {
					t.Fatalf("error unmarshaling response: %s", err.Error())
				}

				if !reflect.DeepEqual(refreshResp, tc.expectedRefreshResp) {
					t.Logf("want: %#v", tc.expectedRefreshResp)
					t.Logf(" got: %#v", refreshResp)
					t.Errorf("got unexpected response")
					return
				}
			}
		})
	}
}

func TestRedeemCode(t *testing.T) {
	testCases := []struct {
		name                 string
		code                 string
		email                string
		providerRedeemError  error
		expectedSessionState *sessions.SessionState
		expectedSessionEmail string
		expectedError        bool
		expectedErrorString  string
	}{
		{
			name:                "with provider Redeem function returning an error",
			code:                "code",
			providerRedeemError: fmt.Errorf("error redeeming"),
			expectedError:       true,
			expectedErrorString: "error redeeming",
		},
		{
			name:                 "no error provider Redeem function, empty email in session state, error on retrieving email address from provider",
			code:                 "code",
			expectedSessionState: &sessions.SessionState{},
			expectedError:        true,
			expectedErrorString:  "no email included in session",
		},
		{
			name: "no error provider Redeem function, email in session state",
			code: "code",
			expectedSessionState: &sessions.SessionState{
				Email:           "emailAddress",
				AccessToken:     "accessToken",
				RefreshDeadline: time.Now(),
				RefreshToken:    "refreshToken",
			},
			expectedSessionEmail: "emailAddress",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			opts := testOpts("client_id", "client_secret")
			opts.Validate()

			proxy, _ := NewAuthenticator(opts, func(p *Authenticator) error {
				p.Validator = func(string) bool { return true }
				return nil
			})

			testURL, err := url.Parse("example.com")
			if err != nil {
				t.Fatalf("error parsing url %s", err.Error())
			}
			proxy.redirectURL = testURL
			testProvider := providers.NewTestProvider(testURL)
			testProvider.RedeemError = tc.providerRedeemError
			testProvider.Session = tc.expectedSessionState
			proxy.provider = testProvider
			sessionState, err := proxy.redeemCode(testURL.Host, tc.code)
			if tc.expectedError && err == nil {
				t.Errorf("expected error with message %s but no error was returned", tc.expectedErrorString)
			}
			if !tc.expectedError && err != nil {
				t.Errorf("unexpected error: %s", err.Error())
			}
			if err != nil {
				if tc.expectedErrorString != err.Error() {
					t.Errorf("expected error %s but got error %s", tc.expectedErrorString, err.Error())
				}
				return
			}
			if sessionState.Email != tc.expectedSessionEmail {
				t.Errorf("expected session state email to be %s but was %s", tc.expectedSessionState.Email, sessionState.Email)
			}
			if sessionState.AccessToken != tc.expectedSessionState.AccessToken {
				t.Errorf("expected session state access token to be %s but was %s", tc.expectedSessionState.AccessToken, sessionState.AccessToken)
			}
			if sessionState.RefreshDeadline != tc.expectedSessionState.RefreshDeadline {
				t.Errorf("expected session state email to be %s but was %s", tc.expectedSessionState.RefreshDeadline, sessionState.RefreshDeadline)
			}
			if sessionState.RefreshToken != tc.expectedSessionState.RefreshToken {
				t.Errorf("expected session state refresh token to be %s but was %s", tc.expectedSessionState.RefreshToken, sessionState.RefreshToken)
			}

		})
	}
}

func TestRedeemEndpoint(t *testing.T) {
	testCases := []struct {
		name                        string
		paramsMap                   map[string]string
		sessionState                *sessions.SessionState
		mockCipher                  *aead.MockCipher
		expectedGAPAuthHeader       string
		expectedStatusCode          int
		expectedResponseEmail       string
		expectedResponseAccessToken string
	}{
		{
			name:               "cipher error",
			mockCipher:         &aead.MockCipher{UnmarshalError: fmt.Errorf("mock cipher error")},
			expectedStatusCode: http.StatusUnauthorized,
		},
		{
			name:       "refresh deadline expired for session state",
			mockCipher: &aead.MockCipher{},
			paramsMap: map[string]string{
				"code": "code",
			},
			sessionState: &sessions.SessionState{
				Email:            "email",
				RefreshToken:     "refresh",
				AccessToken:      "accesstoken",
				RefreshDeadline:  time.Now().Add(-time.Hour),
				LifetimeDeadline: time.Now().Add(time.Hour),
			},
			expectedStatusCode: http.StatusUnauthorized,
		},
		{
			name:       "lifetime deadline expired for session state",
			mockCipher: &aead.MockCipher{},
			paramsMap: map[string]string{
				"code": "code",
			},
			sessionState: &sessions.SessionState{
				Email:            "email",
				RefreshToken:     "refresh",
				AccessToken:      "accesstoken",
				RefreshDeadline:  time.Now().Add(time.Hour),
				LifetimeDeadline: time.Now().Add(-time.Hour),
			},
			expectedStatusCode: http.StatusUnauthorized,
		},
		{
			name:               "empty session returned",
			mockCipher:         &aead.MockCipher{},
			expectedStatusCode: http.StatusUnauthorized,
		},

		{
			name:       "all valid",
			mockCipher: &aead.MockCipher{},
			sessionState: &sessions.SessionState{
				RefreshDeadline:  time.Now().Add(time.Hour),
				Email:            "example@test.com",
				LifetimeDeadline: time.Now().Add(time.Hour),
				AccessToken:      "authToken",
				RefreshToken:     "",
			},
			expectedStatusCode:          http.StatusOK,
			expectedGAPAuthHeader:       "example@test.com",
			expectedResponseEmail:       "example@test.com",
			expectedResponseAccessToken: "authToken",
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			opts := testOpts("client_id", "client_secret")
			opts.Validate()
			p, _ := NewAuthenticator(opts, setMockAuthCodeCipher(tc.mockCipher, tc.sessionState),
				setMockSessionStore(&sessions.MockSessionStore{}))

			params := url.Values{}
			for k, v := range tc.paramsMap {
				params.Set(k, v)
			}

			req := httptest.NewRequest("POST", "/", bytes.NewBufferString(params.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			rw := httptest.NewRecorder()
			p.Redeem(rw, req)
			resp := rw.Result()
			testutil.Equal(t, tc.expectedStatusCode, resp.StatusCode)

			respBytes, err := ioutil.ReadAll(resp.Body)
			if err != nil {
				t.Fatalf("error reading response body: %s", err.Error())
			}
			type redeemResponse struct {
				AccessToken  string `json:"access_token"`
				RefreshToken string `json:"refresh_token"`
				ExpiresIn    int64  `json:"expires_in"`
				Email        string `json:"email"`
			}
			if resp.StatusCode == http.StatusOK {
				redeemResp := redeemResponse{}
				err = json.Unmarshal(respBytes, &redeemResp)
				if err != nil {
					t.Fatalf("error unmarshaling response: %s", err.Error())
				}
				if redeemResp.Email != tc.expectedResponseEmail {
					t.Errorf("expected redeem response email to be %s but was %s",
						tc.expectedResponseEmail, redeemResp.Email)
				}

				if redeemResp.AccessToken != tc.expectedResponseAccessToken {
					t.Errorf("expected redeem access token  to be %s but was %s",
						tc.expectedResponseAccessToken, redeemResp.AccessToken)
				}

				if resp.Header.Get("GAP-Auth") != tc.expectedGAPAuthHeader {
					t.Errorf("expected GAP-Auth response header to be %s but was %s", tc.expectedGAPAuthHeader, resp.Header.Get("GAP-Auth"))
				}
			}
		})
	}
}

type testRedeemResponse struct {
	SessionState *sessions.SessionState
	Error        error
}

func TestOAuthCallback(t *testing.T) {
	testCases := []struct {
		name               string
		paramsMap          map[string]string
		expectedError      error
		testRedeemResponse testRedeemResponse
		validEmail         bool
		csrfResp           *sessions.MockCSRFStore
		sessionStore       *sessions.MockSessionStore
		expectedRedirect   string
	}{
		{
			name: "error string in request",
			paramsMap: map[string]string{
				"error": "request error",
			},
			expectedError: httputil.HTTPError{Code: http.StatusForbidden, Message: "request error"},
		},
		{
			name:          "no code in request",
			paramsMap:     map[string]string{},
			expectedError: httputil.HTTPError{Code: http.StatusBadRequest, Message: "Missing Code"},
		},
		{
			name: "no state in request",
			paramsMap: map[string]string{
				"code": "authCode",
			},
			testRedeemResponse: testRedeemResponse{
				SessionState: &sessions.SessionState{
					Email:           "example@email.com",
					AccessToken:     "accessToken",
					RefreshDeadline: time.Now().Add(time.Hour),
					RefreshToken:    "refresh",
				},
			},
			expectedError: httputil.HTTPError{Code: http.StatusInternalServerError, Message: "Invalid State"},
		},
		{
			name: "redeem response error",
			paramsMap: map[string]string{
				"code": "authCode",
			},
			testRedeemResponse: testRedeemResponse{
				Error: fmt.Errorf("redeem error"),
			},
			expectedError: fmt.Errorf("redeem error"),
		},
		{
			name: "invalid state in request, not base64 encoded",
			paramsMap: map[string]string{
				"code":  "authCode",
				"state": "invalidState",
			},
			testRedeemResponse: testRedeemResponse{
				SessionState: &sessions.SessionState{
					Email:           "example@email.com",
					AccessToken:     "accessToken",
					RefreshDeadline: time.Now().Add(time.Hour),
					RefreshToken:    "refresh",
				},
			},
			expectedError: httputil.HTTPError{Code: http.StatusInternalServerError, Message: "Invalid State"},
		},
		{
			name: "invalid state in request, not in format nonce:redirect_uri",
			paramsMap: map[string]string{
				"code":  "authCode",
				"state": base64.URLEncoding.EncodeToString([]byte("invalidState")),
			},
			testRedeemResponse: testRedeemResponse{
				SessionState: &sessions.SessionState{
					Email:           "example@email.com",
					AccessToken:     "accessToken",
					RefreshDeadline: time.Now().Add(time.Hour),
					RefreshToken:    "refresh",
				},
			},
			expectedError: httputil.HTTPError{Code: http.StatusInternalServerError, Message: "Invalid State"},
		},
		{
			name: "CSRF cookie not present",
			paramsMap: map[string]string{
				"code":  "authCode",
				"state": base64.URLEncoding.EncodeToString([]byte("state:something")),
			},
			testRedeemResponse: testRedeemResponse{
				SessionState: &sessions.SessionState{
					Email:           "example@email.com",
					AccessToken:     "accessToken",
					RefreshDeadline: time.Now().Add(time.Hour),
					RefreshToken:    "refresh",
				},
			},
			csrfResp: &sessions.MockCSRFStore{
				GetError: http.ErrNoCookie,
			},
			expectedError: httputil.HTTPError{Code: http.StatusForbidden, Message: "Missing CSRF token"},
		},
		{
			name: "CSRF cookie value doesn't match state nonce",
			paramsMap: map[string]string{
				"code":  "authCode",
				"state": base64.URLEncoding.EncodeToString([]byte("state:something")),
			},
			testRedeemResponse: testRedeemResponse{
				SessionState: &sessions.SessionState{
					Email:           "example@email.com",
					AccessToken:     "accessToken",
					RefreshDeadline: time.Now().Add(time.Hour),
					RefreshToken:    "refresh",
				},
			},

			csrfResp: &sessions.MockCSRFStore{
				Cookie: &http.Cookie{
					Name:  "something_csrf",
					Value: "notstate",
				},
			},
			expectedError: httputil.HTTPError{Code: http.StatusForbidden, Message: "csrf failed"},
		},

		{
			name: "invalid email address",
			paramsMap: map[string]string{
				"code":  "authCode",
				"state": base64.URLEncoding.EncodeToString([]byte("state:http://www.example.com/something")),
			},
			testRedeemResponse: testRedeemResponse{
				SessionState: &sessions.SessionState{
					Email:           "example@email.com",
					AccessToken:     "accessToken",
					RefreshDeadline: time.Now().Add(time.Hour),
					RefreshToken:    "refresh",
				},
			},
			csrfResp: &sessions.MockCSRFStore{
				Cookie: &http.Cookie{
					Name:  "something_csrf",
					Value: "state",
				},
			},
			expectedError: httputil.HTTPError{Code: http.StatusForbidden, Message: "Invalid Account"},
		},
		{
			name: "valid email, invalid redirect",
			paramsMap: map[string]string{
				"code":  "authCode",
				"state": base64.URLEncoding.EncodeToString([]byte("state:something")),
			},
			testRedeemResponse: testRedeemResponse{
				SessionState: &sessions.SessionState{
					Email:           "example@email.com",
					AccessToken:     "accessToken",
					RefreshDeadline: time.Now().Add(time.Hour),
					RefreshToken:    "refresh",
				},
			},
			csrfResp: &sessions.MockCSRFStore{
				Cookie: &http.Cookie{
					Name:  "something_csrf",
					Value: "state",
				},
			},
			validEmail:    true,
			expectedError: httputil.HTTPError{Code: http.StatusForbidden, Message: "Invalid Redirect URI"},
		},
		{
			name: "valid email, valid redirect, save error",
			paramsMap: map[string]string{
				"code":  "authCode",
				"state": base64.URLEncoding.EncodeToString([]byte("state:http://www.example.com/something")),
			},
			testRedeemResponse: testRedeemResponse{
				SessionState: &sessions.SessionState{
					Email:           "example@email.com",
					AccessToken:     "accessToken",
					RefreshDeadline: time.Now().Add(time.Hour),
					RefreshToken:    "refresh",
				},
			},
			csrfResp: &sessions.MockCSRFStore{
				Cookie: &http.Cookie{
					Name:  "something_csrf",
					Value: "state",
				},
			},
			sessionStore: &sessions.MockSessionStore{
				SaveError: fmt.Errorf("saveError"),
			},
			validEmail:    true,
			expectedError: httputil.HTTPError{Code: http.StatusInternalServerError, Message: "Internal Error"},
		},
		{
			name: "valid email, valid redirect, valid save",
			paramsMap: map[string]string{
				"code":  "authCode",
				"state": base64.URLEncoding.EncodeToString([]byte("state:http://www.example.com/something")),
			},
			testRedeemResponse: testRedeemResponse{
				SessionState: &sessions.SessionState{
					Email:           "example@email.com",
					AccessToken:     "accessToken",
					RefreshDeadline: time.Now().Add(time.Hour),
					RefreshToken:    "refresh",
				},
			},
			csrfResp: &sessions.MockCSRFStore{
				Cookie: &http.Cookie{
					Name:  "something_csrf",
					Value: "state",
				},
			},
			sessionStore:     &sessions.MockSessionStore{},
			validEmail:       true,
			expectedRedirect: "http://www.example.com/something",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			opts := testOpts("client_id", "client_secret")
			opts.Validate()
			proxy, _ := NewAuthenticator(opts, func(p *Authenticator) error {
				p.Validator = func(string) bool { return tc.validEmail }
				return nil
			}, setMockCSRFStore(tc.csrfResp), setMockSessionStore(tc.sessionStore))

			testURL, err := url.Parse("http://example.com")
			if err != nil {
				t.Fatalf("error parsing test url: %s", err.Error())
			}
			proxy.redirectURL = testURL
			testProvider := providers.NewTestProvider(testURL)
			testProvider.Session = tc.testRedeemResponse.SessionState
			testProvider.RedeemError = tc.testRedeemResponse.Error
			proxy.provider = testProvider

			params := &url.Values{}
			for param, val := range tc.paramsMap {
				params.Set(param, val)
			}

			rawQuery := params.Encode()
			req := httptest.NewRequest("GET", fmt.Sprintf("/?%s", rawQuery), nil)

			rw := httptest.NewRecorder()
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

			redirect, err := proxy.getOAuthCallback(rw, req)
			testutil.Equal(t, tc.expectedError, err)
			if err == nil {
				testutil.Equal(t, tc.expectedRedirect, redirect)
				switch store := proxy.csrfStore.(type) {
				case *sessions.MockCSRFStore:
					testutil.Equal(t, store.ResponseCSRF, "")
				default:
					t.Errorf("invalid csrf store with type %t", store)
				}
			}
		})

	}
}

func TestGlobalHeaders(t *testing.T) {
	opts := testOpts("abced", "testtest")
	opts.Validate()
	proxy, _ := NewAuthenticator(opts, setMockCSRFStore(&sessions.MockCSRFStore{}))

	// see middleware.go
	expectedHeaders := securityHeaders

	testCases := []struct {
		path string
	}{
		{"/oauth2/callback"},
		{"/ping"},
		{"/profile"},
		{"/redeem"},
		{"/robots.txt"},
		{"/sign_in"},
		{"/sign_out"},
		{"/start"},
		{"/validate"},
		// even 404s get headers set
		{"/unknown"},
	}

	for _, tc := range testCases {
		t.Run(tc.path, func(t *testing.T) {
			rw := httptest.NewRecorder()
			req, _ := http.NewRequest("GET", tc.path, nil)
			proxy.Handler().ServeHTTP(rw, req)
			for key, expectedVal := range expectedHeaders {
				gotVal := rw.Header().Get(key)
				if gotVal != expectedVal {
					t.Errorf("expected %s=%q, got %s=%q", key, expectedVal, key, gotVal)
				}
			}
		})
	}
}

func TestOAuthStart(t *testing.T) {

	testCases := []struct {
		Name               string
		RedirectURI        string
		ProxyRedirectURI   string
		ExpectedStatusCode int
	}{
		{
			Name:               "reject requests without a redirect",
			ExpectedStatusCode: http.StatusBadRequest,
		},
		{
			Name:               "reject requests with a malicious auth",
			RedirectURI:        "https://auth.evil.com/sign_in",
			ExpectedStatusCode: http.StatusBadRequest,
		},
		{
			Name:               "reject requests without a nested redirect",
			RedirectURI:        "https://auth.example.com/sign_in",
			ExpectedStatusCode: http.StatusBadRequest,
		},
		{
			Name:               "reject requests with a malicious proxy",
			RedirectURI:        "https://auth.example.com/sign_in",
			ProxyRedirectURI:   "https://proxy.evil.com/path/to/badness",
			ExpectedStatusCode: http.StatusBadRequest,
		},
		{
			Name:               "accept requests with good redirect_uris",
			RedirectURI:        "https://auth.example.com/sign_in",
			ProxyRedirectURI:   "https://proxy.example.com/oauth/callback",
			ExpectedStatusCode: http.StatusFound,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {

			opts := testOpts("abced", "testtest")
			redirectURL, _ := url.Parse("https://example.com/oauth2/callback")
			opts.RedirectURL = redirectURL
			opts.Validate()
			u, _ := url.Parse("http://example.com")
			provider := providers.NewTestProvider(u)
			proxy, _ := NewAuthenticator(opts, setTestProvider(provider), func(p *Authenticator) error {
				p.Validator = func(string) bool { return true }
				return nil
			}, setMockCSRFStore(&sessions.MockCSRFStore{}))

			params := url.Values{}
			if tc.RedirectURI != "" {
				redirectURL, _ := url.Parse(tc.RedirectURI)
				if tc.ProxyRedirectURI != "" {
					// NOTE: redirect signatures tested in middleware_test.go
					now := time.Now()
					sig := redirectURLSignature(tc.ProxyRedirectURI, now, "testtest")
					b64sig := base64.URLEncoding.EncodeToString(sig)
					redirectParams := url.Values{}
					redirectParams.Add("redirect_uri", tc.ProxyRedirectURI)
					redirectParams.Add("sig", b64sig)
					redirectParams.Add("ts", fmt.Sprint(now.Unix()))
					redirectURL.RawQuery = redirectParams.Encode()
				}
				params.Add("redirect_uri", redirectURL.String())
			}

			req := httptest.NewRequest("GET", "/start?"+params.Encode(), nil)
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

			rw := httptest.NewRecorder()
			proxy.Handler().ServeHTTP(rw, req)

			if rw.Code != tc.ExpectedStatusCode {
				t.Errorf("expected status code %v but response status code is %v", tc.ExpectedStatusCode, rw.Code)
			}

		})
	}
}

func TestHostHeader(t *testing.T) {
	testCases := []struct {
		Name               string
		Host               string
		RequestHost        string
		Path               string
		ExpectedStatusCode int
	}{
		// {
		// 	Name:               "reject requests with an invalid hostname",
		// 	Host:               "example.com",
		// 	RequestHost:        "unknown.com",
		// 	Path:               "/robots.txt",
		// 	ExpectedStatusCode: http.StatusNotFound,
		// },
		{
			Name:               "allow requests to any hostname to /ping",
			Host:               "example.com",
			RequestHost:        "unknown.com",
			Path:               "/ping",
			ExpectedStatusCode: http.StatusOK,
		},
		{
			Name:               "allow requests with a valid hostname",
			Host:               "example.com",
			RequestHost:        "example.com",
			Path:               "/robots.txt",
			ExpectedStatusCode: http.StatusOK,
		},
	}
	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			opts := testOpts("abced", "testtest")
			opts.Host = tc.Host
			opts.Validate()

			proxy, _ := NewAuthenticator(opts, func(p *Authenticator) error {
				p.Validator = func(string) bool { return true }
				return nil
			})

			uri := fmt.Sprintf("http://%s%s", tc.RequestHost, tc.Path)
			rw := httptest.NewRecorder()
			req, _ := http.NewRequest("GET", uri, nil)
			proxy.Handler().ServeHTTP(rw, req)
			if rw.Code != tc.ExpectedStatusCode {
				t.Errorf("got unexpected status code")
				t.Errorf("want %v", tc.ExpectedStatusCode)
				t.Errorf(" got %v", rw.Code)
				t.Errorf(" headers %v", rw)
				t.Errorf(" body: %q", rw.Body)
			}
		})
	}
}

func Test_dotPrependDomains(t *testing.T) {
	tests := []struct {
		name string
		d    []string
		want []string
	}{
		{"empty", []string{""}, []string{""}},
		{"standard", []string{"google.com"}, []string{".google.com"}},
		{"already has dot", []string{".google.com"}, []string{".google.com"}},
		{"subdomain", []string{"www.google.com"}, []string{".www.google.com"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := dotPrependDomains(tt.d); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("dotPrependDomains() = %v, want %v", got, tt.want)
			}
		})
	}
}
