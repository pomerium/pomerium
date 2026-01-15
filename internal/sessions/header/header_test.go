package header

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

func TestTokenFromHeader(t *testing.T) {
	t.Parallel()
	t.Run("pomerium header", func(t *testing.T) {
		t.Parallel()
		r, _ := http.NewRequest(http.MethodGet, "http://localhost/some/url", nil)
		r.Header.Set("X-Pomerium-Authorization", "JWT")
		v := TokenFromHeaders(r)
		assert.Equal(t, "JWT", v)
	})
	t.Run("pomerium type", func(t *testing.T) {
		t.Parallel()
		r, _ := http.NewRequest(http.MethodGet, "http://localhost/some/url", nil)
		r.Header.Set("Authorization", "Pomerium JWT")
		v := TokenFromHeaders(r)
		assert.Equal(t, "JWT", v)
	})
	t.Run("bearer type", func(t *testing.T) {
		t.Parallel()
		r, _ := http.NewRequest(http.MethodGet, "http://localhost/some/url", nil)
		r.Header.Set("Authorization", "Bearer Pomerium-JWT")
		v := TokenFromHeaders(r)
		assert.Equal(t, "JWT", v)
	})
}

func TestReadSessionHandleJWT(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		authType string
		handle   *session.Handle
		err      error
	}{
		{
			"good auth header session",
			"Pomerium ",
			&session.Handle{},
			nil,
		},
		{
			"empty auth header",
			"Pomerium ",
			&session.Handle{},
			sessions.ErrNoSessionFound,
		},
		{
			"bad auth type",
			"bees ",
			&session.Handle{},
			sessions.ErrNoSessionFound,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
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

			if strings.Contains(tt.name, "empty") {
				encSession = []byte("")
			}
			r.Header.Set("Authorization", tt.authType+string(encSession))

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
