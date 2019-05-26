package sessions

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
	"time"

	"github.com/pomerium/pomerium/internal/cryptutil"
)

type mockCipher struct{}

func (a mockCipher) Encrypt(s []byte) ([]byte, error) {
	if string(s) == "error" {
		return []byte(""), errors.New("error encrypting")
	}
	return []byte("OK"), nil
}

func (a mockCipher) Decrypt(s []byte) ([]byte, error) {
	if string(s) == "error" {
		return []byte(""), errors.New("error encrypting")
	}
	return []byte("OK"), nil
}
func (a mockCipher) Marshal(s interface{}) (string, error) { return "", errors.New("error") }
func (a mockCipher) Unmarshal(s string, i interface{}) error {
	if string(s) == "unmarshal error" || string(s) == "error" {
		return errors.New("error")
	}
	return nil
}
func TestNewCookieStore(t *testing.T) {
	cipher, err := cryptutil.NewCipher(cryptutil.GenerateKey())
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name    string
		opts    *CookieStoreOptions
		want    *CookieStore
		wantErr bool
	}{
		{"good",
			&CookieStoreOptions{
				Name:           "_cookie",
				CookieSecure:   true,
				CookieHTTPOnly: true,
				CookieDomain:   "pomerium.io",
				CookieExpire:   10 * time.Second,
				CookieCipher:   cipher,
			},
			&CookieStore{
				Name:           "_cookie",
				CookieSecure:   true,
				CookieHTTPOnly: true,
				CookieDomain:   "pomerium.io",
				CookieExpire:   10 * time.Second,
				CookieCipher:   cipher,
			},
			false},
		{"missing name",
			&CookieStoreOptions{
				Name:           "",
				CookieSecure:   true,
				CookieHTTPOnly: true,
				CookieDomain:   "pomerium.io",
				CookieExpire:   10 * time.Second,
				CookieCipher:   cipher,
			},
			nil,
			true},
		{"missing cipher",
			&CookieStoreOptions{
				Name:           "_pomerium",
				CookieSecure:   true,
				CookieHTTPOnly: true,
				CookieDomain:   "pomerium.io",
				CookieExpire:   10 * time.Second,
				CookieCipher:   nil,
			},
			nil,
			true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NewCookieStore(tt.opts)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewCookieStore() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("NewCookieStore() = %#v, want %#v", got, tt.want)
			}
		})
	}
}

func TestCookieStore_makeCookie(t *testing.T) {
	cipher, err := cryptutil.NewCipher(cryptutil.GenerateKey())
	if err != nil {
		t.Fatal(err)
	}

	now := time.Now()
	tests := []struct {
		name   string
		domain string

		cookieName string
		value      string
		expiration time.Duration
		want       *http.Cookie
		wantCSRF   *http.Cookie
	}{
		{"good", "http://httpbin.corp.pomerium.io", "_pomerium", "value", 0, &http.Cookie{Name: "_pomerium", Value: "value", Path: "/", Domain: "corp.pomerium.io", Secure: true, HttpOnly: true}, &http.Cookie{Name: "_pomerium_csrf", Value: "value", Path: "/", Domain: "httpbin.corp.pomerium.io", Secure: true, HttpOnly: true}},
		{"domains with https", "https://httpbin.corp.pomerium.io", "_pomerium", "value", 0, &http.Cookie{Name: "_pomerium", Value: "value", Path: "/", Domain: "corp.pomerium.io", Secure: true, HttpOnly: true}, &http.Cookie{Name: "_pomerium_csrf", Value: "value", Path: "/", Domain: "httpbin.corp.pomerium.io", Secure: true, HttpOnly: true}},
		{"domain with port", "http://httpbin.corp.pomerium.io:443", "_pomerium", "value", 0, &http.Cookie{Name: "_pomerium", Value: "value", Path: "/", Domain: "corp.pomerium.io", Secure: true, HttpOnly: true}, &http.Cookie{Name: "_pomerium_csrf", Value: "value", Path: "/", Domain: "httpbin.corp.pomerium.io", Secure: true, HttpOnly: true}},
		{"expiration set", "http://httpbin.corp.pomerium.io:443", "_pomerium", "value", 10 * time.Second, &http.Cookie{Expires: now.Add(10 * time.Second), Name: "_pomerium", Value: "value", Path: "/", Domain: "corp.pomerium.io", Secure: true, HttpOnly: true}, &http.Cookie{Expires: now.Add(10 * time.Second), Name: "_pomerium_csrf", Value: "value", Path: "/", Domain: "httpbin.corp.pomerium.io", Secure: true, HttpOnly: true}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := httptest.NewRequest("GET", tt.domain, nil)

			o := &CookieStoreOptions{
				Name:           "_pomerium",
				CookieSecure:   true,
				CookieHTTPOnly: true,
				CookieDomain:   "httpbin.corp.pomerium.io",
				CookieExpire:   10 * time.Second,
				CookieCipher:   cipher}

			s, _ := NewCookieStore(o)
			if got := s.makeCookie(r, tt.cookieName, tt.value, tt.expiration, now); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("CookieStore.makeCookie() = \n%#v, \nwant\n%#v", got, tt.want)
			}
			if got := s.makeSessionCookie(r, tt.value, tt.expiration, now); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("CookieStore.makeCookie() = \n%#v, \nwant\n%#v", got, tt.want)
			}
			got := s.makeCSRFCookie(r, tt.value, tt.expiration, now)
			tt.wantCSRF.Name = "_pomerium_csrf"
			if !reflect.DeepEqual(got, tt.wantCSRF) {
				t.Errorf("CookieStore.makeCookie() = \n%#v, \nwant\n%#v", got, tt.wantCSRF)
			}
			w := httptest.NewRecorder()
			want := "new-csrf"
			s.SetCSRF(w, r, want)
			found := false
			for _, cookie := range w.Result().Cookies() {
				if cookie.Name == s.Name+"_csrf" && cookie.Value == want {
					found = true
					break
				}
			}
			if !found {
				t.Error("SetCSRF failed")
			}

			w = httptest.NewRecorder()
			s.ClearCSRF(w, r)
			for _, cookie := range w.Result().Cookies() {
				if cookie.Name == s.Name+"_csrf" && cookie.Value == want {
					t.Error("clear csrf failed")
					break

				}
			}
			w = httptest.NewRecorder()
			want = "new-session"
			s.setSessionCookie(w, r, want)
			found = false
			for _, cookie := range w.Result().Cookies() {
				if cookie.Name == s.Name && cookie.Value == want {
					found = true
					break
				}
			}
			if !found {
				t.Error("SetCSRF failed")
			}
			w = httptest.NewRecorder()
			s.ClearSession(w, r)
			for _, cookie := range w.Result().Cookies() {
				if cookie.Name == s.Name && cookie.Value == want {
					t.Error("clear csrf failed")
					break
				}
			}

		})
	}
}

func TestCookieStore_SaveSession(t *testing.T) {
	cipher, err := cryptutil.NewCipher(cryptutil.GenerateKey())
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name         string
		sessionState *SessionState
		cipher       cryptutil.Cipher
		wantErr      bool
		wantLoadErr  bool
	}{
		{"good",
			&SessionState{
				AccessToken:     "token1234",
				RefreshToken:    "refresh4321",
				RefreshDeadline: time.Now().Add(1 * time.Hour).Truncate(time.Second).UTC(),
				Email:           "user@domain.com",
				User:            "user",
			}, cipher, false, false},
		{"bad cipher",
			&SessionState{
				AccessToken:     "token1234",
				RefreshToken:    "refresh4321",
				RefreshDeadline: time.Now().Add(1 * time.Hour).Truncate(time.Second).UTC(),
				Email:           "user@domain.com",
				User:            "user",
			}, mockCipher{}, true, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &CookieStore{
				Name:           "_pomerium",
				CookieSecure:   true,
				CookieHTTPOnly: true,
				CookieDomain:   "pomerium.io",
				CookieExpire:   10 * time.Second,
				CookieCipher:   tt.cipher}

			r := httptest.NewRequest("GET", "/", nil)
			w := httptest.NewRecorder()

			if err := s.SaveSession(w, r, tt.sessionState); (err != nil) != tt.wantErr {
				t.Errorf("CookieStore.SaveSession() error = %v, wantErr %v", err, tt.wantErr)
			}
			r = httptest.NewRequest("GET", "/", nil)
			for _, cookie := range w.Result().Cookies() {
				t.Log(cookie)
				r.AddCookie(cookie)
			}

			state, err := s.LoadSession(r)
			if (err != nil) != tt.wantLoadErr {
				t.Errorf("LoadSession() error = %v, wantErr %v", err, tt.wantLoadErr)
				return
			}
			if err == nil && !reflect.DeepEqual(state, tt.sessionState) {
				t.Errorf("CookieStore.LoadSession() got = \n%v, want \n%v", state, tt.sessionState)
			}
		})
	}
}

func TestMockCSRFStore(t *testing.T) {
	tests := []struct {
		name         string
		mockCSRF     *MockCSRFStore
		newCSRFValue string
		wantErr      bool
	}{
		{"basic",
			&MockCSRFStore{
				ResponseCSRF: "ok",
				Cookie:       &http.Cookie{Name: "hi"}},
			"newcsrf",
			false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ms := tt.mockCSRF
			ms.SetCSRF(nil, nil, tt.newCSRFValue)
			ms.ClearCSRF(nil, nil)
			got, err := ms.GetCSRF(nil)
			if (err != nil) != tt.wantErr {
				t.Errorf("MockCSRFStore.GetCSRF() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.mockCSRF.Cookie) {
				t.Errorf("MockCSRFStore.GetCSRF() = %v, want %v", got, tt.mockCSRF.Cookie)
			}

		})
	}
}

func TestMockSessionStore(t *testing.T) {
	tests := []struct {
		name        string
		mockCSRF    *MockSessionStore
		saveSession *SessionState
		wantLoadErr bool
		wantSaveErr bool
	}{
		{"basic",
			&MockSessionStore{
				ResponseSession: "test",
				Session:         &SessionState{AccessToken: "AccessToken"},
				SaveError:       nil,
				LoadError:       nil,
			},
			&SessionState{AccessToken: "AccessToken"},
			false,
			false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ms := tt.mockCSRF

			err := ms.SaveSession(nil, nil, tt.saveSession)
			if (err != nil) != tt.wantSaveErr {
				t.Errorf("MockCSRFStore.GetCSRF() error = %v, wantSaveErr %v", err, tt.wantSaveErr)
				return
			}
			got, err := ms.LoadSession(nil)
			if (err != nil) != tt.wantLoadErr {
				t.Errorf("MockCSRFStore.GetCSRF() error = %v, wantLoadErr %v", err, tt.wantLoadErr)
				return
			}
			if !reflect.DeepEqual(got, tt.mockCSRF.Session) {
				t.Errorf("MockCSRFStore.GetCSRF() = %v, want %v", got, tt.mockCSRF.Session)
			}
			ms.ClearSession(nil, nil)
			if ms.ResponseSession != "" {
				t.Errorf("ResponseSession not empty! %s", ms.ResponseSession)
			}
		})
	}
}

func Test_splitDomain(t *testing.T) {
	t.Parallel()
	tests := []struct {
		s    string
		want string
	}{
		{"httpbin.corp.example.com", "corp.example.com"},
		{"some.httpbin.corp.example.com", "httpbin.corp.example.com"},
		{"example.com", ""},
		{"", ""},
	}
	for _, tt := range tests {
		t.Run(tt.s, func(t *testing.T) {
			if got := splitDomain(tt.s); got != tt.want {
				t.Errorf("splitDomain() = %v, want %v", got, tt.want)
			}
		})
	}
}
