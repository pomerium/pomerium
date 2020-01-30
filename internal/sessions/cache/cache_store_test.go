package cache

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/pomerium/pomerium/internal/cryptutil"
	"github.com/pomerium/pomerium/internal/encoding"
	"github.com/pomerium/pomerium/internal/encoding/ecjson"
	mock_encoder "github.com/pomerium/pomerium/internal/encoding/mock"
	"github.com/pomerium/pomerium/internal/grpc/cache/client"
	"github.com/pomerium/pomerium/internal/sessions"
	"github.com/pomerium/pomerium/internal/sessions/cookie"
	"github.com/pomerium/pomerium/internal/sessions/mock"
	"gopkg.in/square/go-jose.v2/jwt"
)

type mockCache struct {
	Key       string
	KeyExists bool
	Value     []byte
	Err       error
}

func (mc *mockCache) Get(ctx context.Context, key string) (keyExists bool, value []byte, err error) {
	return mc.KeyExists, mc.Value, mc.Err
}
func (mc *mockCache) Set(ctx context.Context, key string, value []byte) error {
	return mc.Err
}
func (mc *mockCache) Close() error {
	return mc.Err
}

func TestNewStore(t *testing.T) {

	tests := []struct {
		name    string
		Options *Options
		State   *sessions.State

		wantErr     bool
		wantLoadErr bool
		wantStatus  int
	}{
		{"simple good",
			&Options{
				Cache:        &mockCache{},
				WrappedStore: &mock.Store{},
				Encoder:      mock_encoder.Encoder{MarshalResponse: []byte("ok")},
			},
			&sessions.State{Email: "user@domain.com", User: "user"},
			false, false,
			http.StatusOK},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := NewStore(tt.Options)

			r := httptest.NewRequest("GET", "/", nil)
			w := httptest.NewRecorder()

			if err := got.SaveSession(w, r, tt.State); (err != nil) != tt.wantErr {
				t.Errorf("NewStore.SaveSession() error = %v, wantErr %v", err, tt.wantErr)
			}

			r = httptest.NewRequest("GET", "/", nil)
			w = httptest.NewRecorder()

			got.ClearSession(w, r)
			status := w.Result().StatusCode
			if diff := cmp.Diff(status, tt.wantStatus); diff != "" {
				t.Errorf("ClearSession() = %v", diff)
			}
		})
	}
}

func TestStore_SaveSession(t *testing.T) {
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
	tests := []struct {
		name    string
		Options *Options

		x       interface{}
		wantErr bool
	}{
		{"good", &Options{Cache: &mockCache{}, WrappedStore: cs, Encoder: mock_encoder.Encoder{MarshalResponse: []byte("ok")}}, &sessions.State{AccessTokenID: cryptutil.NewBase64Key(), Email: "user@pomerium.io", Expiry: jwt.NewNumericDate(time.Now().Add(10 * time.Minute))}, false},
		{"encoder error", &Options{Cache: &mockCache{}, WrappedStore: cs, Encoder: mock_encoder.Encoder{MarshalError: errors.New("err")}}, &sessions.State{AccessTokenID: cryptutil.NewBase64Key(), Email: "user@pomerium.io", Expiry: jwt.NewNumericDate(time.Now().Add(10 * time.Minute))}, true},
		{"good", &Options{Cache: &mockCache{}, WrappedStore: &mock.Store{SaveError: errors.New("err")}}, &sessions.State{AccessTokenID: cryptutil.NewBase64Key(), Email: "user@pomerium.io", Expiry: jwt.NewNumericDate(time.Now().Add(10 * time.Minute))}, true},
		{"bad type", &Options{Cache: &mockCache{}, WrappedStore: cs, Encoder: mock_encoder.Encoder{MarshalError: errors.New("err")}}, "bad type!", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			o := tt.Options
			if o.WrappedStore == nil {
				o.WrappedStore = cs

			}
			cacheStore := NewStore(tt.Options)
			r := httptest.NewRequest(http.MethodGet, "/", nil)
			r.Header.Set("Accept", "application/json")
			w := httptest.NewRecorder()
			if err := cacheStore.SaveSession(w, r, tt.x); (err != nil) != tt.wantErr {
				t.Errorf("Store.SaveSession() error = %v, wantErr %v", err, tt.wantErr)
			}

		})
	}
}

func TestStore_LoadSession(t *testing.T) {
	key := cryptutil.NewBase64Key()
	tests := []struct {
		name         string
		state        *sessions.State
		cache        client.Cacher
		encoder      encoding.MarshalUnmarshaler
		queryParam   string
		wrappedStore sessions.SessionStore
		wantErr      bool
	}{
		{"good",
			&sessions.State{AccessTokenID: key, Email: "user@pomerium.io"},
			&mockCache{KeyExists: true},
			mock_encoder.Encoder{MarshalResponse: []byte("ok")},
			defaultOptions.QueryParam,
			&mock.Store{Session: &sessions.State{AccessTokenID: key, Email: "user@pomerium.io"}},
			false},
		{"missing param with key",
			&sessions.State{AccessTokenID: key, Email: "user@pomerium.io"},
			&mockCache{KeyExists: true},
			mock_encoder.Encoder{MarshalResponse: []byte("ok")},
			"bad_query",
			&mock.Store{Session: &sessions.State{AccessTokenID: key, Email: "user@pomerium.io"}},
			true},
		{"doesn't exist",
			&sessions.State{AccessTokenID: key, Email: "user@pomerium.io"},
			&mockCache{KeyExists: false},
			mock_encoder.Encoder{MarshalResponse: []byte("ok")},
			defaultOptions.QueryParam,
			&mock.Store{Session: &sessions.State{AccessTokenID: key, Email: "user@pomerium.io"}},
			true},
		{"retrieval error",
			&sessions.State{AccessTokenID: key, Email: "user@pomerium.io"},
			&mockCache{Err: errors.New("err")},
			mock_encoder.Encoder{MarshalResponse: []byte("ok")},
			defaultOptions.QueryParam,
			&mock.Store{Session: &sessions.State{AccessTokenID: key, Email: "user@pomerium.io"}},
			true},
		{"unmarshal failure",
			&sessions.State{AccessTokenID: key, Email: "user@pomerium.io"},
			&mockCache{KeyExists: true},
			mock_encoder.Encoder{UnmarshalError: errors.New("err")},
			defaultOptions.QueryParam,
			&mock.Store{Session: &sessions.State{AccessTokenID: key, Email: "user@pomerium.io"}},
			true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &Store{
				cache:        tt.cache,
				encoder:      tt.encoder,
				queryParam:   tt.queryParam,
				wrappedStore: tt.wrappedStore,
			}

			r := httptest.NewRequest(http.MethodGet, "/", nil)
			q := r.URL.Query()

			q.Set(defaultOptions.QueryParam, tt.state.AccessTokenID)
			r.URL.RawQuery = q.Encode()
			r.Header.Set("Accept", "application/json")

			_, _, err := s.LoadSession(r)
			if (err != nil) != tt.wantErr {
				t.Errorf("Store.LoadSession() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}
