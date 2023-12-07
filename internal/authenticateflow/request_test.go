package authenticateflow

import (
	"net/http"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/urlutil"
)

func TestVerifyAuthenticateSignature(t *testing.T) {
	options := &config.Options{
		AuthenticateURLString:         "https://authenticate.example.com",
		AuthenticateInternalURLString: "https://authenticate.internal",
	}
	key := []byte("SHARED KEY--(must be 32 bytes)--")
	v := signatureVerifier{options, key}

	t.Run("Valid", func(t *testing.T) {
		u := mustParseURL("https://example.com/")
		r := &http.Request{Host: "example.com", URL: urlutil.NewSignedURL(key, u).Sign()}
		err := v.VerifyAuthenticateSignature(r)
		assert.NoError(t, err)
	})
	t.Run("NoSignature", func(t *testing.T) {
		r := &http.Request{Host: "example.com", URL: mustParseURL("https://example.com/")}
		err := v.VerifyAuthenticateSignature(r)
		assert.Error(t, err)
	})
	t.Run("DifferentKey", func(t *testing.T) {
		zeros := make([]byte, 32)
		u := mustParseURL("https://example.com/")
		r := &http.Request{Host: "example.com", URL: urlutil.NewSignedURL(zeros, u).Sign()}
		err := v.VerifyAuthenticateSignature(r)
		assert.Error(t, err)
	})
	t.Run("InternalDomain", func(t *testing.T) {
		// A request with the internal authenticate service URL should first be
		// canonicalized to use the external authenticate service URL before
		// validating the request signature.
		u := urlutil.NewSignedURL(key, mustParseURL("https://authenticate.example.com/")).Sign()
		u.Host = "authenticate.internal"
		r := &http.Request{Host: "authenticate.internal", URL: u}
		err := v.VerifyAuthenticateSignature(r)
		assert.NoError(t, err)
	})
}

func mustParseURL(rawurl string) *url.URL {
	u, err := url.Parse(rawurl)
	if err != nil {
		panic(err)
	}
	return u
}
