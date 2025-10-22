package authenticate

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pomerium/pomerium/pkg/cryptutil"
)

func TestEnsureTokenSet(t *testing.T) {
	t.Parallel()

	csrf := newCSRFCookieValidation(cryptutil.NewKey(), "_csrf", http.SameSiteLaxMode)

	verifyCookie := func(t *testing.T, rec *httptest.ResponseRecorder) string {
		cookies := rec.Result().Cookies()
		require.Len(t, cookies, 1)
		cookie := cookies[0]
		assert.Equal(t, "_csrf", cookie.Name)
		assert.Empty(t, cookie.Domain)
		assert.True(t, cookie.Secure)
		assert.True(t, cookie.HttpOnly)
		assert.Equal(t, http.SameSiteLaxMode, cookie.SameSite)
		assert.Equal(t, "/", cookie.Path)
		return cookies[0].Value
	}

	t.Run("no cookie", func(t *testing.T) {
		t.Parallel()

		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/example/path", nil)

		csrf.EnsureCookieSet(rec, req)

		// A cookie should be set.
		verifyCookie(t, rec)
	})
	t.Run("valid cookie", func(t *testing.T) {
		t.Parallel()

		existingCookie, existingToken := getCSRFCookieAndTokenForTest(t, csrf)

		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/example/path", nil)
		req.AddCookie(existingCookie)

		token := csrf.EnsureCookieSet(rec, req)

		// The existing cookie should not be modified.
		assert.Empty(t, rec.Result().Cookies())
		assert.Equal(t, existingToken, token)
	})
	t.Run("invalid cookie", func(t *testing.T) {
		t.Parallel()

		// Generate a cookie with a token of the wrong length.
		wrongTokenLength := []byte("abcdefg")
		value, err := csrf.sc.Encode("_csrf", wrongTokenLength)
		require.NoError(t, err)

		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/example/path", nil)

		req.AddCookie(&http.Cookie{
			Name:  "_csrf",
			Value: value,
		})

		csrf.EnsureCookieSet(rec, req)

		// The invalid cookie should be overwritten.
		verifyCookie(t, rec)
	})
}

func TestValidateToken(t *testing.T) {
	t.Parallel()

	csrf := newCSRFCookieValidation(cryptutil.NewKey(), "_csrf", http.SameSiteLaxMode)

	cookie, token := getCSRFCookieAndTokenForTest(t, csrf)
	req := httptest.NewRequest(http.MethodGet, "/example/path", nil)
	req.AddCookie(cookie)

	assert.NoError(t, csrf.ValidateToken(req, token))
	assert.ErrorContains(t, csrf.ValidateToken(req, ""), "invalid CSRF token")
	assert.ErrorContains(t, csrf.ValidateToken(req, "AAA="), "invalid CSRF token")
	assert.ErrorContains(t, csrf.ValidateToken(&http.Request{}, token), "no CSRF cookie")
	assert.ErrorContains(t, csrf.ValidateToken(&http.Request{}, ""), "no CSRF cookie")
}

func getCSRFCookieAndTokenForTest(t *testing.T, csrf *csrfCookieValidation) (*http.Cookie, string) {
	t.Helper()
	rec := httptest.NewRecorder()
	token := csrf.EnsureCookieSet(rec, &http.Request{})
	cookies := rec.Result().Cookies()
	require.Len(t, cookies, 1, "test bug: expected CSRF cookie not set")
	require.Equal(t, csrf.name, cookies[0].Name, "test bug: expected CSRF cookie not set")
	return cookies[0], token
}
