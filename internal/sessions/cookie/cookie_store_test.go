package cookie

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
	"github.com/stretchr/testify/require"

	"github.com/pomerium/pomerium/internal/encoding"
	"github.com/pomerium/pomerium/internal/encoding/jws"
	"github.com/pomerium/pomerium/internal/encoding/mock"
	"github.com/pomerium/pomerium/internal/sessions"
	"github.com/pomerium/pomerium/pkg/cryptutil"
	"github.com/pomerium/pomerium/pkg/grpc/session"
)

func TestNewStore(t *testing.T) {
	key := cryptutil.NewKey()
	encoder, err := jws.NewHS256Signer(key)
	require.NoError(t, err)
	tests := []struct {
		name    string
		opts    *Options
		encoder encoding.MarshalUnmarshaler
		want    sessions.SessionStore
		wantErr bool
	}{
		{"good", &Options{Name: "_cookie", Secure: true, HTTPOnly: true, Domain: "pomerium.io", Expire: 10 * time.Second}, encoder, &Store{getOptions: func() Options {
			return Options{Name: "_cookie", Secure: true, HTTPOnly: true, Domain: "pomerium.io", Expire: 10 * time.Second}
		}}, false},
		{"missing encoder", &Options{Name: "_cookie", Secure: true, HTTPOnly: true, Domain: "pomerium.io", Expire: 10 * time.Second}, nil, nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NewStore(func() Options {
				return *tt.opts
			}, tt.encoder)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewStore() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			cmpOpts := []cmp.Option{
				cmpopts.IgnoreUnexported(Store{}),
			}

			if diff := cmp.Diff(got, tt.want, cmpOpts...); diff != "" {
				t.Errorf("NewStore() = %s", diff)
			}
		})
	}
}

func TestNewCookieLoader(t *testing.T) {
	key := cryptutil.NewKey()
	encoder, err := jws.NewHS256Signer(key)
	require.NoError(t, err)
	tests := []struct {
		name    string
		opts    *Options
		encoder encoding.MarshalUnmarshaler
		want    *Store
		wantErr bool
	}{
		{"good", &Options{Name: "_cookie", Secure: true, HTTPOnly: true, Domain: "pomerium.io", Expire: 10 * time.Second}, encoder, &Store{getOptions: func() Options {
			return Options{Name: "_cookie", Secure: true, HTTPOnly: true, Domain: "pomerium.io", Expire: 10 * time.Second}
		}}, false},
		{"missing encoder", &Options{Name: "_cookie", Secure: true, HTTPOnly: true, Domain: "pomerium.io", Expire: 10 * time.Second}, nil, nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NewCookieLoader(func() Options {
				return *tt.opts
			}, tt.encoder)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewCookieLoader() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			cmpOpts := []cmp.Option{
				cmpopts.IgnoreUnexported(Store{}),
			}

			if diff := cmp.Diff(got, tt.want, cmpOpts...); diff != "" {
				t.Errorf("NewCookieLoader() = %s", diff)
			}
		})
	}
}

func TestStore_SaveSession(t *testing.T) {
	key := cryptutil.NewKey()
	encoder, err := jws.NewHS256Signer(key)
	require.NoError(t, err)

	hugeString := make([]byte, 4097)
	if _, err := rand.Read(hugeString); err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name        string
		State       any
		encoder     encoding.Marshaler
		decoder     encoding.Unmarshaler
		wantErr     bool
		wantLoadErr bool
	}{
		{"good", &session.Handle{Id: "xyz"}, encoder, encoder, false, false},
		{"bad cipher", &session.Handle{Id: "xyz"}, nil, nil, true, true},
		{"huge cookie", &session.Handle{Id: "xyz", UserId: fmt.Sprintf("%x", hugeString)}, encoder, encoder, false, false},
		{"marshal error", &session.Handle{Id: "xyz"}, mock.Encoder{MarshalError: errors.New("error")}, encoder, true, true},
		{"nil encoder cannot save non string type", &session.Handle{Id: "xyz"}, nil, encoder, true, true},
		{"good marshal string directly", cryptutil.NewBase64Key(), nil, encoder, false, true},
		{"good marshal bytes directly", cryptutil.NewKey(), nil, encoder, false, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &Store{
				getOptions: func() Options {
					return Options{
						Name:     "_pomerium",
						Secure:   true,
						HTTPOnly: true,
						Domain:   "pomerium.io",
						Expire:   10 * time.Second,
					}
				},
				encoder: tt.encoder,
				decoder: tt.decoder,
			}

			r := httptest.NewRequest(http.MethodGet, "/", nil)
			w := httptest.NewRecorder()

			if err := s.SaveSession(w, r, tt.State); (err != nil) != tt.wantErr {
				t.Errorf("Store.SaveSession() error = %v, wantErr %v", err, tt.wantErr)
			}
			r = httptest.NewRequest(http.MethodGet, "/", nil)
			for _, cookie := range w.Result().Cookies() {
				r.AddCookie(cookie)
			}

			jwt, err := s.LoadSession(r)
			if (err != nil) != tt.wantLoadErr {
				t.Errorf("LoadSession() error = %v, wantErr %v", err, tt.wantLoadErr)
				return
			}
			var h session.Handle
			encoder.Unmarshal([]byte(jwt), &h)

			cmpOpts := []cmp.Option{
				cmpopts.IgnoreUnexported(session.Handle{}),
			}
			if err == nil {
				if diff := cmp.Diff(&h, tt.State, cmpOpts...); diff != "" {
					t.Errorf("Store.LoadSession() got = %s", diff)
				}
			}
			w = httptest.NewRecorder()
			s.ClearSession(w, r)
			x := w.Header().Get("Set-Cookie")
			if !strings.Contains(x, "_pomerium=; Path=/;") {
				t.Error(x)
			}
		})
	}
}
