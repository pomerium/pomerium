package sessions // import "github.com/pomerium/pomerium/internal/sessions"

import (
	"crypto/rand"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/pomerium/pomerium/internal/cryptutil"
	"github.com/pomerium/pomerium/internal/encoding"
	"github.com/pomerium/pomerium/internal/encoding/ecjson"
)

func TestNewCookieStore(t *testing.T) {
	cipher, err := cryptutil.NewAEADCipher(cryptutil.NewKey())
	if err != nil {
		t.Fatal(err)
	}
	encoder := ecjson.New(cipher)
	tests := []struct {
		name    string
		opts    *CookieOptions
		encoder Encoder
		want    *CookieStore
		wantErr bool
	}{
		{"good", &CookieOptions{Name: "_cookie", Secure: true, HTTPOnly: true, Domain: "pomerium.io", Expire: 10 * time.Second}, encoder, &CookieStore{Name: "_cookie", Secure: true, HTTPOnly: true, Domain: "pomerium.io", Expire: 10 * time.Second}, false},
		{"missing name", &CookieOptions{Name: "", Secure: true, HTTPOnly: true, Domain: "pomerium.io", Expire: 10 * time.Second}, encoder, nil, true},
		{"missing encoder", &CookieOptions{Name: "_cookie", Secure: true, HTTPOnly: true, Domain: "pomerium.io", Expire: 10 * time.Second}, nil, nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NewCookieStore(tt.opts, tt.encoder)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewCookieStore() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			cmpOpts := []cmp.Option{
				cmpopts.IgnoreUnexported(CookieStore{}),
			}

			if diff := cmp.Diff(got, tt.want, cmpOpts...); diff != "" {
				t.Errorf("NewCookieStore() = %s", diff)
			}
		})
	}
}
func TestNewCookieLoader(t *testing.T) {
	cipher, err := cryptutil.NewAEADCipher(cryptutil.NewKey())
	if err != nil {
		t.Fatal(err)
	}
	encoder := ecjson.New(cipher)
	tests := []struct {
		name    string
		opts    *CookieOptions
		encoder Encoder
		want    *CookieStore
		wantErr bool
	}{
		{"good", &CookieOptions{Name: "_cookie", Secure: true, HTTPOnly: true, Domain: "pomerium.io", Expire: 10 * time.Second}, encoder, &CookieStore{Name: "_cookie", Secure: true, HTTPOnly: true, Domain: "pomerium.io", Expire: 10 * time.Second}, false},
		{"missing name", &CookieOptions{Name: "", Secure: true, HTTPOnly: true, Domain: "pomerium.io", Expire: 10 * time.Second}, encoder, nil, true},
		{"missing encoder", &CookieOptions{Name: "_cookie", Secure: true, HTTPOnly: true, Domain: "pomerium.io", Expire: 10 * time.Second}, nil, nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NewCookieLoader(tt.opts, tt.encoder)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewCookieLoader() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			cmpOpts := []cmp.Option{
				cmpopts.IgnoreUnexported(CookieStore{}),
			}

			if diff := cmp.Diff(got, tt.want, cmpOpts...); diff != "" {
				t.Errorf("NewCookieLoader() = %s", diff)
			}
		})
	}
}

func TestCookieStore_makeCookie(t *testing.T) {
	cipher, err := cryptutil.NewAEADCipher(cryptutil.NewKey())

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
		{"good", "http://httpbin.corp.pomerium.io", "", "_pomerium", "value", 0, &http.Cookie{Name: "_pomerium", Value: "value", Path: "/", Domain: "httpbin.corp.pomerium.io", Secure: true, HttpOnly: true}, &http.Cookie{Name: "_pomerium_csrf", Value: "value", Path: "/", Domain: "httpbin.corp.pomerium.io", Secure: true, HttpOnly: true}},
		{"domains with https", "https://httpbin.corp.pomerium.io", "", "_pomerium", "value", 0, &http.Cookie{Name: "_pomerium", Value: "value", Path: "/", Domain: "httpbin.corp.pomerium.io", Secure: true, HttpOnly: true}, &http.Cookie{Name: "_pomerium_csrf", Value: "value", Path: "/", Domain: "httpbin.corp.pomerium.io", Secure: true, HttpOnly: true}},
		{"domain with port", "http://httpbin.corp.pomerium.io:443", "", "_pomerium", "value", 0, &http.Cookie{Name: "_pomerium", Value: "value", Path: "/", Domain: "httpbin.corp.pomerium.io", Secure: true, HttpOnly: true}, &http.Cookie{Name: "_pomerium_csrf", Value: "value", Path: "/", Domain: "httpbin.corp.pomerium.io", Secure: true, HttpOnly: true}},
		{"expiration set", "http://httpbin.corp.pomerium.io:443", "", "_pomerium", "value", 10 * time.Second, &http.Cookie{Expires: now.Add(10 * time.Second), Name: "_pomerium", Value: "value", Path: "/", Domain: "httpbin.corp.pomerium.io", Secure: true, HttpOnly: true}, &http.Cookie{Expires: now.Add(10 * time.Second), Name: "_pomerium_csrf", Value: "value", Path: "/", Domain: "httpbin.corp.pomerium.io", Secure: true, HttpOnly: true}},
		{"good", "http://httpbin.corp.pomerium.io", "pomerium.io", "_pomerium", "value", 0, &http.Cookie{Name: "_pomerium", Value: "value", Path: "/", Domain: "pomerium.io", Secure: true, HttpOnly: true}, &http.Cookie{Name: "_pomerium_csrf", Value: "value", Path: "/", Domain: "httpbin.corp.pomerium.io", Secure: true, HttpOnly: true}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := httptest.NewRequest("GET", tt.domain, nil)

			s, err := NewCookieStore(
				&CookieOptions{
					Name:     "_pomerium",
					Secure:   true,
					HTTPOnly: true,
					Domain:   tt.cookieDomain,
					Expire:   10 * time.Second,
				},
				ecjson.New(cipher))
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
	c, err := cryptutil.NewAEADCipher(cryptutil.NewKey())
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
		encoder     Encoder
		decoder     Encoder
		wantErr     bool
		wantLoadErr bool
	}{
		{"good", &State{Email: "user@domain.com", User: "user"}, ecjson.New(c), ecjson.New(c), false, false},
		{"bad cipher", &State{Email: "user@domain.com", User: "user"}, nil, nil, true, true},
		{"huge cookie", &State{Subject: fmt.Sprintf("%x", hugeString), Email: "user@domain.com", User: "user"}, ecjson.New(c), ecjson.New(c), false, false},
		{"marshal error", &State{Email: "user@domain.com", User: "user"}, encoding.MockEncoder{MarshalError: errors.New("error")}, ecjson.New(c), true, true},
		{"nil encoder cannot save non string type", &State{Email: "user@domain.com", User: "user"}, nil, ecjson.New(c), true, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &CookieStore{
				Name:     "_pomerium",
				Secure:   true,
				HTTPOnly: true,
				Domain:   "pomerium.io",
				Expire:   10 * time.Second,
				encoder:  tt.encoder,
				decoder:  tt.encoder,
			}

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
			cmpOpts := []cmp.Option{
				cmpopts.IgnoreUnexported(State{}),
			}
			if err == nil {
				if diff := cmp.Diff(state, tt.State, cmpOpts...); diff != "" {
					t.Errorf("CookieStore.LoadSession() got = %s", diff)
				}
			}
			w = httptest.NewRecorder()
			s.ClearSession(w, r)
			x := w.Header().Get("Set-Cookie")
			if !strings.Contains(x, "_pomerium=; Path=/;") {
				t.Errorf(x)
			}
		})
	}
}
