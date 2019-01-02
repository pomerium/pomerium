package sessions // import "github.com/pomerium/pomerium/internal/sessions"

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/pomerium/pomerium/internal/testutil"
)

var testEncodedCookieSecret, _ = base64.StdEncoding.DecodeString("qICChm3wdjbjcWymm7PefwtPP6/PZv+udkFEubTeE38=")

func TestCreateMiscreantCookieCipher(t *testing.T) {
	testCases := []struct {
		name          string
		cookieSecret  []byte
		expectedError bool
	}{
		{
			name:         "normal case with base64 encoded secret",
			cookieSecret: testEncodedCookieSecret,
		},

		{
			name:          "error when not base64 encoded",
			cookieSecret:  []byte("abcd"),
			expectedError: true,
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := NewCookieStore("cookieName", CreateMiscreantCookieCipher(tc.cookieSecret))
			if !tc.expectedError {
				testutil.Ok(t, err)
			} else {
				testutil.NotEqual(t, err, nil)
			}
		})
	}
}

func TestNewSession(t *testing.T) {
	testCases := []struct {
		name            string
		optFuncs        []func(*CookieStore) error
		expectedError   bool
		expectedSession *CookieStore
	}{
		{
			name: "default with no opt funcs set",
			expectedSession: &CookieStore{
				Name:           "cookieName",
				CookieSecure:   true,
				CookieHTTPOnly: true,
				CookieExpire:   168 * time.Hour,
				CSRFCookieName: "cookieName_csrf",
			},
		},
		{
			name:          "opt func with an error returns an error",
			optFuncs:      []func(*CookieStore) error{func(*CookieStore) error { return fmt.Errorf("error") }},
			expectedError: true,
		},
		{
			name: "opt func overrides default values",
			optFuncs: []func(*CookieStore) error{func(s *CookieStore) error {
				s.CookieExpire = time.Hour
				return nil
			}},
			expectedSession: &CookieStore{
				Name:           "cookieName",
				CookieSecure:   true,
				CookieHTTPOnly: true,
				CookieExpire:   time.Hour,
				CSRFCookieName: "cookieName_csrf",
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			session, err := NewCookieStore("cookieName", tc.optFuncs...)
			if tc.expectedError {
				testutil.NotEqual(t, err, nil)
			} else {
				testutil.Ok(t, err)
			}
			testutil.Equal(t, tc.expectedSession, session)
		})
	}
}

func TestMakeSessionCookie(t *testing.T) {
	now := time.Now()
	cookieValue := "cookieValue"
	expiration := time.Hour
	cookieName := "cookieName"
	testCases := []struct {
		name           string
		optFuncs       []func(*CookieStore) error
		expectedCookie *http.Cookie
	}{
		{
			name: "default cookie domain",
			expectedCookie: &http.Cookie{
				Name:     cookieName,
				Value:    cookieValue,
				Path:     "/",
				Domain:   "www.example.com",
				HttpOnly: true,
				Secure:   true,
				Expires:  now.Add(expiration),
			},
		},
		{
			name: "custom cookie domain set",
			optFuncs: []func(*CookieStore) error{
				func(s *CookieStore) error {
					s.CookieDomain = "buzzfeed.com"
					return nil
				},
			},
			expectedCookie: &http.Cookie{
				Name:     cookieName,
				Value:    cookieValue,
				Path:     "/",
				Domain:   "buzzfeed.com",
				HttpOnly: true,
				Secure:   true,
				Expires:  now.Add(expiration),
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			session, err := NewCookieStore(cookieName, tc.optFuncs...)
			testutil.Ok(t, err)
			req := httptest.NewRequest("GET", "http://www.example.com", nil)
			cookie := session.makeSessionCookie(req, cookieValue, expiration, now)
			testutil.Equal(t, cookie, tc.expectedCookie)
		})
	}
}

func TestMakeSessionCSRFCookie(t *testing.T) {
	now := time.Now()
	cookieValue := "cookieValue"
	expiration := time.Hour
	cookieName := "cookieName"
	csrfName := "cookieName_csrf"

	testCases := []struct {
		name           string
		optFuncs       []func(*CookieStore) error
		expectedCookie *http.Cookie
	}{
		{
			name: "default cookie domain",
			expectedCookie: &http.Cookie{
				Name:     csrfName,
				Value:    cookieValue,
				Path:     "/",
				Domain:   "www.example.com",
				HttpOnly: true,
				Secure:   true,
				Expires:  now.Add(expiration),
			},
		},
		{
			name: "custom cookie domain set",
			optFuncs: []func(*CookieStore) error{
				func(s *CookieStore) error {
					s.CookieDomain = "buzzfeed.com"
					return nil
				},
			},
			expectedCookie: &http.Cookie{
				Name:     csrfName,
				Value:    cookieValue,
				Path:     "/",
				Domain:   "buzzfeed.com",
				HttpOnly: true,
				Secure:   true,
				Expires:  now.Add(expiration),
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			session, err := NewCookieStore(cookieName, tc.optFuncs...)
			testutil.Ok(t, err)
			req := httptest.NewRequest("GET", "http://www.example.com", nil)
			cookie := session.makeCSRFCookie(req, cookieValue, expiration, now)
			testutil.Equal(t, tc.expectedCookie, cookie)
		})
	}
}

func TestSetSessionCookie(t *testing.T) {
	cookieValue := "cookieValue"
	cookieName := "cookieName"

	t.Run("set session cookie test", func(t *testing.T) {
		session, err := NewCookieStore(cookieName)
		testutil.Ok(t, err)
		req := httptest.NewRequest("GET", "http://www.example.com", nil)
		rw := httptest.NewRecorder()
		session.setSessionCookie(rw, req, cookieValue)
		var found bool
		for _, cookie := range rw.Result().Cookies() {
			if cookie.Name == cookieName {
				found = true
				testutil.Equal(t, cookieValue, cookie.Value)
				testutil.Assert(t, cookie.Expires.After(time.Now()), "cookie expires after now")
			}
		}
		testutil.Assert(t, found, "cookie in header")
	})
}
func TestSetCSRFSessionCookie(t *testing.T) {
	cookieValue := "cookieValue"
	cookieName := "cookieName"

	t.Run("set csrf cookie test", func(t *testing.T) {
		session, err := NewCookieStore(cookieName)
		testutil.Ok(t, err)
		req := httptest.NewRequest("GET", "http://www.example.com", nil)
		rw := httptest.NewRecorder()
		session.SetCSRF(rw, req, cookieValue)
		var found bool
		for _, cookie := range rw.Result().Cookies() {
			if cookie.Name == fmt.Sprintf("%s_csrf", cookieName) {
				found = true
				testutil.Equal(t, cookieValue, cookie.Value)
				testutil.Assert(t, cookie.Expires.After(time.Now()), "cookie expires after now")
			}
		}
		testutil.Assert(t, found, "cookie in header")
	})
}

func TestClearSessionCookie(t *testing.T) {
	cookieValue := "cookieValue"
	cookieName := "cookieName"

	t.Run("set session cookie test", func(t *testing.T) {
		session, err := NewCookieStore(cookieName)
		testutil.Ok(t, err)
		req := httptest.NewRequest("GET", "http://www.example.com", nil)
		req.AddCookie(session.makeSessionCookie(req, cookieValue, time.Hour, time.Now()))

		rw := httptest.NewRecorder()
		session.ClearSession(rw, req)
		var found bool
		for _, cookie := range rw.Result().Cookies() {
			if cookie.Name == cookieName {
				found = true
				testutil.Equal(t, "", cookie.Value)
				testutil.Assert(t, cookie.Expires.Before(time.Now()), "cookie expires before now")
			}
		}
		testutil.Assert(t, found, "cookie in header")
	})
}

func TestClearCSRFSessionCookie(t *testing.T) {
	cookieValue := "cookieValue"
	cookieName := "cookieName"

	t.Run("clear csrf cookie test", func(t *testing.T) {
		session, err := NewCookieStore(cookieName)
		testutil.Ok(t, err)
		req := httptest.NewRequest("GET", "http://www.example.com", nil)
		req.AddCookie(session.makeCSRFCookie(req, cookieValue, time.Hour, time.Now()))

		rw := httptest.NewRecorder()
		session.ClearCSRF(rw, req)
		var found bool
		for _, cookie := range rw.Result().Cookies() {
			if cookie.Name == fmt.Sprintf("%s_csrf", cookieName) {
				found = true
				testutil.Equal(t, "", cookie.Value)
				testutil.Assert(t, cookie.Expires.Before(time.Now()), "cookie expires before now")
			}
		}
		testutil.Assert(t, found, "cookie in header")
	})
}

func TestLoadCookiedSession(t *testing.T) {
	cookieName := "cookieName"

	testCases := []struct {
		name          string
		optFuncs      []func(*CookieStore) error
		setupCookies  func(*testing.T, *http.Request, *CookieStore, *SessionState)
		expectedError error
		sessionState  *SessionState
	}{
		{
			name:          "no cookie set returns an error",
			setupCookies:  func(*testing.T, *http.Request, *CookieStore, *SessionState) {},
			expectedError: http.ErrNoCookie,
		},
		{
			name:     "cookie set with cipher set",
			optFuncs: []func(*CookieStore) error{CreateMiscreantCookieCipher(testEncodedCookieSecret)},
			setupCookies: func(t *testing.T, req *http.Request, s *CookieStore, sessionState *SessionState) {
				value, err := MarshalSession(sessionState, s.CookieCipher)
				testutil.Ok(t, err)
				req.AddCookie(s.makeSessionCookie(req, value, time.Hour, time.Now()))
			},
			sessionState: &SessionState{
				Email:        "example@email.com",
				RefreshToken: "abccdddd",
				AccessToken:  "access",
			},
		},
		{
			name:     "cookie set with invalid value cipher set",
			optFuncs: []func(*CookieStore) error{CreateMiscreantCookieCipher(testEncodedCookieSecret)},
			setupCookies: func(t *testing.T, req *http.Request, s *CookieStore, sessionState *SessionState) {
				value := "574b776a7c934d6b9fc42ec63a389f79"
				req.AddCookie(s.makeSessionCookie(req, value, time.Hour, time.Now()))
			},
			expectedError: ErrInvalidSession,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			session, err := NewCookieStore(cookieName, tc.optFuncs...)
			testutil.Ok(t, err)
			req := httptest.NewRequest("GET", "https://www.example.com", nil)
			tc.setupCookies(t, req, session, tc.sessionState)
			s, err := session.LoadSession(req)

			testutil.Equal(t, tc.expectedError, err)
			testutil.Equal(t, tc.sessionState, s)

		})
	}
}
