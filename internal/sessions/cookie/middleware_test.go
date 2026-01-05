package cookie

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pomerium/pomerium/internal/encoding/jws"
	"github.com/pomerium/pomerium/pkg/cryptutil"
	"github.com/pomerium/pomerium/pkg/grpc/session"
)

func TestLoad(t *testing.T) {
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

			cs, err := NewStore(func() Options {
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

			rawJWT, err := cs.LoadSession(r)
			assert.NoError(t, err)
			assert.Equal(t, string(encSession), rawJWT)
		})
	}
}
