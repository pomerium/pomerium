package queryparam

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pomerium/pomerium/internal/encoding/jws"
	"github.com/pomerium/pomerium/internal/sessions"
	"github.com/pomerium/pomerium/pkg/cryptutil"
	"github.com/pomerium/pomerium/pkg/grpc/session"
)

func TestReadSessionHandleJWT(t *testing.T) {
	tests := []struct {
		name   string
		handle *session.Handle
		err    error
	}{
		{"good auth query param session", &session.Handle{}, nil},
		{"empty auth query param", &session.Handle{}, sessions.ErrNoSessionFound},
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

			s := New(encoder)

			r := httptest.NewRequest(http.MethodGet, "/", nil)
			r.Header.Set("Accept", "application/json")

			q := r.URL.Query()
			if strings.Contains(tt.name, "empty") {
				encSession = []byte("")
			}
			q.Set("pomerium_session", string(encSession))
			r.URL.RawQuery = q.Encode()

			rawJWT, err := s.ReadSessionHandleJWT(r)
			if tt.err == nil {
				assert.NoError(t, err)
				assert.Equal(t, string(encSession), string(rawJWT))
			} else {
				assert.ErrorIs(t, err, tt.err)
			}
		})
	}
}
