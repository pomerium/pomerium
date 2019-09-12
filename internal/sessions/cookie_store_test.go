package sessions // import "github.com/pomerium/pomerium/internal/sessions"

import (
	"crypto/rand"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
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
	if s == "unmarshal error" || s == "error" {
		return errors.New("error")
	}
	return nil
}
func TestNewCookieStore(t *testing.T) {
	cipher, err := cryptutil.NewCipher(cryptutil.NewKey())
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
				Name:              "_cookie",
				CookieSecure:      true,
				CookieHTTPOnly:    true,
				CookieDomain:      "pomerium.io",
				CookieExpire:      10 * time.Second,
				CookieCipher:      cipher,
				BearerTokenHeader: "Authorization",
			},
			&CookieStore{
				Name:              "_cookie",
				CookieSecure:      true,
				CookieHTTPOnly:    true,
				CookieDomain:      "pomerium.io",
				CookieExpire:      10 * time.Second,
				CookieCipher:      cipher,
				BearerTokenHeader: "Authorization",
			},
			false},
		{"missing name",
			&CookieStoreOptions{
				Name:              "",
				CookieSecure:      true,
				CookieHTTPOnly:    true,
				CookieDomain:      "pomerium.io",
				CookieExpire:      10 * time.Second,
				CookieCipher:      cipher,
				BearerTokenHeader: "Authorization",
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
			cmpOpts := []cmp.Option{
				cmpopts.IgnoreUnexported(cryptutil.XChaCha20Cipher{}),
			}

			if diff := cmp.Diff(got, tt.want, cmpOpts...); diff != "" {
				t.Errorf("NewCookieStore() = %s", diff)
			}
		})
	}
}

func TestCookieStore_makeCookie(t *testing.T) {
	cipher, err := cryptutil.NewCipher(cryptutil.NewKey())
	if err != nil {
		t.Fatal(err)
	}

	now := time.Now()
	tests := []struct {
		name   string
		domain string

		cookieDomain string
		cookieName   string
		value        string
		expiration   time.Duration
		want         *http.Cookie
		wantCSRF     *http.Cookie
	}{
		{"good", "http://httpbin.corp.pomerium.io", "", "_pomerium", "value", 0, &http.Cookie{Name: "_pomerium", Value: "value", Path: "/", Domain: "corp.pomerium.io", Secure: true, HttpOnly: true}, &http.Cookie{Name: "_pomerium_csrf", Value: "value", Path: "/", Domain: "httpbin.corp.pomerium.io", Secure: true, HttpOnly: true}},
		{"domains with https", "https://httpbin.corp.pomerium.io", "", "_pomerium", "value", 0, &http.Cookie{Name: "_pomerium", Value: "value", Path: "/", Domain: "corp.pomerium.io", Secure: true, HttpOnly: true}, &http.Cookie{Name: "_pomerium_csrf", Value: "value", Path: "/", Domain: "httpbin.corp.pomerium.io", Secure: true, HttpOnly: true}},
		{"domain with port", "http://httpbin.corp.pomerium.io:443", "", "_pomerium", "value", 0, &http.Cookie{Name: "_pomerium", Value: "value", Path: "/", Domain: "corp.pomerium.io", Secure: true, HttpOnly: true}, &http.Cookie{Name: "_pomerium_csrf", Value: "value", Path: "/", Domain: "httpbin.corp.pomerium.io", Secure: true, HttpOnly: true}},
		{"expiration set", "http://httpbin.corp.pomerium.io:443", "", "_pomerium", "value", 10 * time.Second, &http.Cookie{Expires: now.Add(10 * time.Second), Name: "_pomerium", Value: "value", Path: "/", Domain: "corp.pomerium.io", Secure: true, HttpOnly: true}, &http.Cookie{Expires: now.Add(10 * time.Second), Name: "_pomerium_csrf", Value: "value", Path: "/", Domain: "httpbin.corp.pomerium.io", Secure: true, HttpOnly: true}},
		{"good", "http://httpbin.corp.pomerium.io", "pomerium.io", "_pomerium", "value", 0, &http.Cookie{Name: "_pomerium", Value: "value", Path: "/", Domain: "pomerium.io", Secure: true, HttpOnly: true}, &http.Cookie{Name: "_pomerium_csrf", Value: "value", Path: "/", Domain: "httpbin.corp.pomerium.io", Secure: true, HttpOnly: true}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := httptest.NewRequest("GET", tt.domain, nil)

			s, err := NewCookieStore(
				&CookieStoreOptions{
					Name:           "_pomerium",
					CookieSecure:   true,
					CookieHTTPOnly: true,
					CookieDomain:   tt.cookieDomain,
					CookieExpire:   10 * time.Second,
					CookieCipher:   cipher})
			if err != nil {
				t.Fatal(err)
			}
			if diff := cmp.Diff(s.makeCookie(r, tt.cookieName, tt.value, tt.expiration, now), tt.want); diff != "" {
				t.Errorf("CookieStore.makeCookie() = \n%s", diff)
			}
			if diff := cmp.Diff(s.makeSessionCookie(r, tt.value, tt.expiration, now), tt.want); diff != "" {
				t.Errorf("CookieStore.makeSessionCookie() = \n%s", diff)
			}

		})
	}
}

func TestCookieStore_SaveSession(t *testing.T) {
	cipher, err := cryptutil.NewCipher(cryptutil.NewKey())
	if err != nil {
		t.Fatal(err)
	}
	hugeString := make([]byte, 4097)
	if _, err := rand.Read(hugeString); err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name        string
		State       *State
		cipher      cryptutil.Cipher
		wantErr     bool
		wantLoadErr bool
	}{
		{"good", &State{AccessToken: "token1234", RefreshToken: "refresh4321", RefreshDeadline: time.Now().Add(1 * time.Hour).Truncate(time.Second).UTC(), Email: "user@domain.com", User: "user"}, cipher, false, false},
		{"bad cipher", &State{AccessToken: "token1234", RefreshToken: "refresh4321", RefreshDeadline: time.Now().Add(1 * time.Hour).Truncate(time.Second).UTC(), Email: "user@domain.com", User: "user"}, mockCipher{}, true, true},
		{"huge cookie", &State{AccessToken: fmt.Sprintf("%x", hugeString), RefreshToken: "refresh4321", RefreshDeadline: time.Now().Add(1 * time.Hour).Truncate(time.Second).UTC(), Email: "user@domain.com", User: "user"}, cipher, false, false},
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

			if err := s.SaveSession(w, r, tt.State); (err != nil) != tt.wantErr {
				t.Errorf("CookieStore.SaveSession() error = %v, wantErr %v", err, tt.wantErr)
			}
			r = httptest.NewRequest("GET", "/", nil)
			for _, cookie := range w.Result().Cookies() {
				// t.Log(cookie)
				r.AddCookie(cookie)
			}

			state, err := s.LoadSession(r)
			if (err != nil) != tt.wantLoadErr {
				t.Errorf("LoadSession() error = %v, wantErr %v", err, tt.wantLoadErr)
				return
			}
			if err == nil {
				if diff := cmp.Diff(state, tt.State); diff != "" {
					t.Errorf("CookieStore.LoadSession() got = %s", diff)
				}
			}
		})
	}
}

func TestMockSessionStore(t *testing.T) {
	tests := []struct {
		name        string
		mockCSRF    *MockSessionStore
		saveSession *State
		wantLoadErr bool
		wantSaveErr bool
	}{
		{"basic",
			&MockSessionStore{
				ResponseSession: "test",
				Session:         &State{AccessToken: "AccessToken"},
				SaveError:       nil,
				LoadError:       nil,
			},
			&State{AccessToken: "AccessToken"},
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

func Test_ParentSubdomain(t *testing.T) {
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
			if got := ParentSubdomain(tt.s); got != tt.want {
				t.Errorf("ParentSubdomain() = %v, want %v", got, tt.want)
			}
		})
	}
}
