package sessions_test

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/testing/protocmp"

	"github.com/pomerium/pomerium/internal/sessions"
	"github.com/pomerium/pomerium/internal/urlutil"
	"github.com/pomerium/pomerium/pkg/grpc/session"
)

func TestSessionHandleReader(t *testing.T) {
	t.Parallel()

	k1 := bytes.Repeat([]byte{0x01}, 32)
	k2 := bytes.Repeat([]byte{0x02}, 32)
	h1 := &session.Handle{
		Id:                      "ID",
		UserId:                  "USER_ID",
		Audience:                []string{"AUDIENCE1", "AUDIENCE2"},
		IdpId:                   "IDP_ID",
		DataBrokerServerVersion: 1234,
		DataBrokerRecordVersion: 5678,
	}
	rawJWT, err := session.MarshalAndSignHandle(k1, h1)
	require.NoError(t, err)
	r := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "https://www.example.com", nil)

	t.Run("cookie", func(t *testing.T) {
		t.Parallel()

		r1 := r.Clone(t.Context())
		r1.AddCookie(&http.Cookie{
			Name:  "_test",
			Value: rawJWT,
		})

		h2, err := sessions.NewSessionHandleReader(k1, "_test").ReadSessionHandle(r1)
		assert.NoError(t, err)
		assert.Empty(t, cmp.Diff(h1, h2, protocmp.Transform()))

		h2, err = sessions.NewSessionHandleReader(k1, "_test2").ReadSessionHandle(r1)
		assert.ErrorIs(t, err, sessions.ErrSessionHandleNotFound)
		assert.Nil(t, h2)

		h2, err = sessions.NewSessionHandleReader(k2, "_test").ReadSessionHandle(r1)
		assert.ErrorIs(t, err, sessions.ErrSessionHandleMalformed)
		assert.Nil(t, h2)
	})
	t.Run("header", func(t *testing.T) {
		t.Parallel()

		r1 := r.Clone(t.Context())
		r1.Header.Set("X-Pomerium-Authorization", rawJWT)
		h2, err := sessions.NewSessionHandleReader(k1, "_test").ReadSessionHandle(r1)
		assert.NoError(t, err)
		assert.Empty(t, cmp.Diff(h1, h2, protocmp.Transform()))

		r2 := r.Clone(t.Context())
		r2.Header.Set("Authorization", "Pomerium "+rawJWT)
		h2, err = sessions.NewSessionHandleReader(k1, "_test").ReadSessionHandle(r2)
		assert.NoError(t, err)
		assert.Empty(t, cmp.Diff(h1, h2, protocmp.Transform()))

		r3 := r.Clone(t.Context())
		r3.Header.Set("Authorization", "Bearer Pomerium-"+rawJWT)
		h2, err = sessions.NewSessionHandleReader(k1, "_test").ReadSessionHandle(r3)
		assert.NoError(t, err)
		assert.Empty(t, cmp.Diff(h1, h2, protocmp.Transform()))

		h2, err = sessions.NewSessionHandleReader(k2, "_test").ReadSessionHandle(r3)
		assert.ErrorIs(t, err, sessions.ErrSessionHandleMalformed)
		assert.Nil(t, h2)
	})
	t.Run("query", func(t *testing.T) {
		t.Parallel()

		r := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "https://www.example.com?"+(url.Values{
			urlutil.QuerySession: {rawJWT},
		}).Encode(), nil)
		h2, err := sessions.NewSessionHandleReader(k1, "_test").ReadSessionHandle(r)
		assert.NoError(t, err)
		assert.Empty(t, cmp.Diff(h1, h2, protocmp.Transform()))

		h2, err = sessions.NewSessionHandleReader(k2, "_test").ReadSessionHandle(r)
		assert.ErrorIs(t, err, sessions.ErrSessionHandleMalformed)
		assert.Nil(t, h2)
	})
}

func TestSessionHandleWriter(t *testing.T) {
	t.Parallel()

	k1 := bytes.Repeat([]byte{0x01}, 32)
	h := &session.Handle{
		Id:                      "ID",
		UserId:                  "USER_ID",
		Audience:                []string{"AUDIENCE1", "AUDIENCE2"},
		IdpId:                   "IDP_ID",
		DataBrokerServerVersion: 1234,
		DataBrokerRecordVersion: 5678,
	}
	rawJWT, err := session.MarshalAndSignHandle(k1, h)
	require.NoError(t, err)

	shw := sessions.NewSessionHandleWriter(k1, "_session", "example.com", time.Hour, true, http.SameSiteStrictMode)
	w := httptest.NewRecorder()
	assert.NoError(t, shw.WriteSessionHandle(w, h))

	if assert.Len(t, w.Result().Cookies(), 1) {
		c := w.Result().Cookies()[0]
		assert.Equal(t, "_session", c.Name)
		assert.Equal(t, "example.com", c.Domain)
		assert.True(t, c.Expires.Before(time.Now().Add(2*time.Hour)))
		assert.True(t, c.HttpOnly)
		assert.True(t, c.Secure)
		assert.Equal(t, http.SameSiteStrictMode, c.SameSite)
		assert.Equal(t, rawJWT, c.Value)
	}
}
