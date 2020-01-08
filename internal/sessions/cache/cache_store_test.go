package cache

import (
	"context"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/pomerium/pomerium/internal/cryptutil"
	"github.com/pomerium/pomerium/internal/encoding/ecjson"
	"github.com/pomerium/pomerium/internal/sessions"
	"github.com/pomerium/pomerium/internal/sessions/cookie"
	"github.com/pomerium/pomerium/internal/urlutil"
	"gopkg.in/square/go-jose.v2/jwt"
)

func testAuthorizer(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, err := sessions.FromContext(r.Context())
		if err != nil {
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func TestVerifier(t *testing.T) {
	fnh := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		fmt.Fprint(w, http.StatusText(http.StatusOK))
		w.WriteHeader(http.StatusOK)
	})

	tests := []struct {
		name      string
		skipSave  bool
		cacheSize int64
		state     sessions.State

		wantBody   string
		wantStatus int
	}{
		{"good", false, 1 << 10, sessions.State{AccessTokenID: cryptutil.NewBase64Key(), Email: "user@pomerium.io", Expiry: jwt.NewNumericDate(time.Now().Add(10 * time.Minute))}, http.StatusText(http.StatusOK), http.StatusOK},
		{"expired", false, 1 << 10, sessions.State{AccessTokenID: cryptutil.NewBase64Key(), Email: "user@pomerium.io", Expiry: jwt.NewNumericDate(time.Now().Add(-10 * time.Minute))}, "internal/sessions: validation failed, token is expired (exp)\n", http.StatusUnauthorized},
		{"empty", false, 1 << 10, sessions.State{AccessTokenID: "", Email: "user@pomerium.io", Expiry: jwt.NewNumericDate(time.Now().Add(-10 * time.Minute))}, "internal/sessions: session is not found\n", http.StatusUnauthorized},
		{"miss", true, 1 << 10, sessions.State{AccessTokenID: cryptutil.NewBase64Key(), Email: "user@pomerium.io", Expiry: jwt.NewNumericDate(time.Now().Add(10 * time.Minute))}, "internal/sessions: session is not found\n", http.StatusUnauthorized},
		{"cache eviction", false, 1, sessions.State{AccessTokenID: cryptutil.NewBase64Key(), Email: "user@pomerium.io", Expiry: jwt.NewNumericDate(time.Now().Add(10 * time.Minute))}, "internal/sessions: session is not found\n", http.StatusUnauthorized},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			defaultCacheSize = tt.cacheSize
			cipher, err := cryptutil.NewAEADCipherFromBase64(cryptutil.NewBase64Key())
			encoder := ecjson.New(cipher)
			if err != nil {
				t.Fatal(err)
			}
			cs, err := cookie.NewStore(&cookie.Options{Name: t.Name()}, encoder)
			if err != nil {
				t.Fatal(err)
			}
			cacheStore := NewStore(encoder, cs, t.Name(), "sharedSecret")

			r := httptest.NewRequest(http.MethodGet, "/", nil)
			q := r.URL.Query()

			q.Set(defaultQueryParamKey, tt.state.AccessTokenID)
			r.URL.RawQuery = q.Encode()
			r.Header.Set("Accept", "application/json")
			w := httptest.NewRecorder()

			got := sessions.RetrieveSession(cacheStore)(testAuthorizer((fnh)))

			if !tt.skipSave {
				cacheStore.SaveSession(w, r, &tt.state)
			}

			for i := 1; i <= 10; i++ {
				s := tt.state
				s.AccessTokenID = cryptutil.NewBase64Key()
				cacheStore.SaveSession(w, r, s)
			}

			got.ServeHTTP(w, r)

			gotBody := w.Body.String()
			gotStatus := w.Result().StatusCode

			if diff := cmp.Diff(gotBody, tt.wantBody); diff != "" {
				t.Errorf("RetrieveSession() = %v", diff)
			}
			if diff := cmp.Diff(gotStatus, tt.wantStatus); diff != "" {
				t.Errorf("RetrieveSession() = %v", diff)
			}
		})
	}
}

func TestStore_SaveSession(t *testing.T) {
	tests := []struct {
		name    string
		x       interface{}
		wantErr bool
	}{
		{"good", &sessions.State{AccessTokenID: cryptutil.NewBase64Key(), Email: "user@pomerium.io", Expiry: jwt.NewNumericDate(time.Now().Add(10 * time.Minute))}, false},
		{"bad type", "bad type!", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cipher, err := cryptutil.NewAEADCipherFromBase64(cryptutil.NewBase64Key())
			encoder := ecjson.New(cipher)
			if err != nil {
				t.Fatal(err)
			}
			cs, err := cookie.NewStore(&cookie.Options{
				Name: "_pomerium",
			}, encoder)
			if err != nil {
				t.Fatal(err)
			}
			cacheStore := NewStore(encoder, cs, t.Name(), "shared secret")
			r := httptest.NewRequest(http.MethodGet, "/", nil)
			r.Header.Set("Accept", "application/json")
			w := httptest.NewRecorder()

			if err := cacheStore.SaveSession(w, r, tt.x); (err != nil) != tt.wantErr {
				t.Errorf("Store.SaveSession() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestStore_AddSessionToCtx(t *testing.T) {
	tests := []struct {
		name      string
		serverKey string
		clientKey string
		payload   []byte
		wantErr   bool
	}{
		{"good", "secretA", "secretA", []byte("some session data!"), false},
		{"bad hmac", "secretA", "secretB", []byte("some session data!"), true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &Store{sharedKey: tt.serverKey}
			ts := httptest.NewServer(
				QueryParamToCtx(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.Header().Set("payload", string(fromContext(r.Context())))
					fmt.Fprintf(w, "%s", urlutil.GetAbsoluteURL(r).String())
				})))
			defer ts.Close()
			client := ts.Client()
			client.Transport = s.AddSessionToCtx(newContext(context.TODO(), tt.payload))
			res, err := client.Get(ts.URL + "/") // trailing slash fails hmac lol
			if err != nil {
				log.Fatal(err)
			}
			out, err := ioutil.ReadAll(res.Body)
			res.Body.Close()
			if err != nil {
				log.Fatal("bad closer", err)
			}
			outURL, err := url.Parse(string(out))
			if err != nil {
				log.Fatal(err)
			}
			u := urlutil.NewSignedURL(tt.clientKey, outURL)

			err = u.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("want hmac error() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			payloadOut := res.Header.Get("payload")
			if diff := cmp.Diff(string(tt.payload), payloadOut); diff != "" {
				t.Errorf("AddSessionToCtx() = %s", diff)
			}
		})
	}
}
