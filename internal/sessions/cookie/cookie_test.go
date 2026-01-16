package cookie

import (
	"crypto/rand"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pomerium/pomerium/internal/encoding"
	"github.com/pomerium/pomerium/internal/encoding/jws"
	"github.com/pomerium/pomerium/internal/encoding/mock"
	"github.com/pomerium/pomerium/internal/sessions"
	"github.com/pomerium/pomerium/pkg/cryptutil"
	"github.com/pomerium/pomerium/pkg/grpc/session"
)

func TestNew(t *testing.T) {
	key := cryptutil.NewKey()
	encoder, err := jws.NewHS256Signer(key)
	require.NoError(t, err)
	tests := []struct {
		name    string
		opts    *Options
		encoder encoding.MarshalUnmarshaler
		want    sessions.HandleWriter
		wantErr bool
	}{
		{"good", &Options{Name: "_cookie", Secure: true, HTTPOnly: true, Domain: "pomerium.io", Expire: 10 * time.Second}, encoder, &handleReaderWriter{getOptions: func() Options {
			return Options{Name: "_cookie", Secure: true, HTTPOnly: true, Domain: "pomerium.io", Expire: 10 * time.Second}
		}}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := New(func() Options {
				return *tt.opts
			}, tt.encoder)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewStore() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			cmpOpts := []cmp.Option{
				cmpopts.IgnoreUnexported(handleReaderWriter{}),
			}

			if diff := cmp.Diff(got, tt.want, cmpOpts...); diff != "" {
				t.Errorf("NewStore() = %s", diff)
			}
		})
	}
}

func TestWriteSessionHandle(t *testing.T) {
	key := cryptutil.NewKey()
	encoder, err := jws.NewHS256Signer(key)
	require.NoError(t, err)

	hugeString := make([]byte, 4097)
	if _, err := rand.Read(hugeString); err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name        string
		State       *session.Handle
		encoder     encoding.MarshalUnmarshaler
		wantErr     bool
		wantLoadErr bool
	}{
		{"good", &session.Handle{Id: "xyz"}, encoder, false, false},
		{"marshal error", &session.Handle{Id: "xyz"}, mock.Encoder{MarshalError: errors.New("error")}, true, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &handleReaderWriter{
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
			}

			r := httptest.NewRequest(http.MethodGet, "/", nil)
			w := httptest.NewRecorder()

			if err := s.WriteSessionHandle(w, tt.State); (err != nil) != tt.wantErr {
				t.Errorf("Store.SaveSession() error = %v, wantErr %v", err, tt.wantErr)
			}
			r = httptest.NewRequest(http.MethodGet, "/", nil)
			for _, cookie := range w.Result().Cookies() {
				r.AddCookie(cookie)
			}

			rawJWT, err := s.ReadSessionHandleJWT(r)
			if (err != nil) != tt.wantLoadErr {
				t.Errorf("LoadSession() error = %v, wantErr %v", err, tt.wantLoadErr)
				return
			}
			var h session.Handle
			encoder.Unmarshal(rawJWT, &h)

			cmpOpts := []cmp.Option{
				cmpopts.IgnoreUnexported(session.Handle{}),
			}
			if err == nil {
				if diff := cmp.Diff(&h, tt.State, cmpOpts...); diff != "" {
					t.Errorf("Store.LoadSession() got = %s", diff)
				}
			}
			w = httptest.NewRecorder()
			s.ClearSessionHandle(w)
			x := w.Header().Get("Set-Cookie")
			if !strings.Contains(x, "_pomerium=; Path=/;") {
				t.Error(x)
			}
		})
	}
}

func TestReadSessionHandleJWT(t *testing.T) {
	tests := []struct {
		name   string
		handle *session.Handle

		wantBody   string
		wantStatus int
	}{
		{
			"good cookie session",
			&session.Handle{Id: "xyz"},
			http.StatusText(http.StatusOK),
			http.StatusOK,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key := cryptutil.NewKey()
			encoder, err := jws.NewHS256Signer(key)
			require.NoError(t, err)
			encSession, err := encoder.Marshal(tt.handle)
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(tt.name, "malformed") {
				// add some garbage to the end of the string
				encSession = append(encSession, cryptutil.NewKey()...)
			}

			cs, err := New(func() Options {
				return Options{
					Name: "_pomerium",
				}
			}, encoder)
			if err != nil {
				t.Fatal(err)
			}

			r := httptest.NewRequest(http.MethodGet, "/", nil)
			r.Header.Set("Accept", "application/json")
			r.AddCookie(&http.Cookie{Name: "_pomerium", Value: string(encSession)})

			rawJWT, err := cs.ReadSessionHandleJWT(r)
			assert.NoError(t, err)
			assert.Equal(t, string(encSession), string(rawJWT))
		})
	}
}
