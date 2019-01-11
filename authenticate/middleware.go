package authenticate // import "github.com/pomerium/pomerium/authenticate"

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/pomerium/pomerium/internal/httputil"
)

var defaultSignatureValidityDuration = 5 * time.Minute

// validateRedirectURI checks the redirect uri in the query parameters and ensures that
// the url's domain is one in the list of proxy root domains.
func validateRedirectURI(f http.HandlerFunc, proxyRootDomains []string) http.HandlerFunc {
	return func(rw http.ResponseWriter, req *http.Request) {
		err := req.ParseForm()
		if err != nil {
			httputil.ErrorResponse(rw, req, err.Error(), http.StatusBadRequest)
			return
		}
		redirectURI := req.Form.Get("redirect_uri")
		if !validRedirectURI(redirectURI, proxyRootDomains) {
			httputil.ErrorResponse(rw, req, "Invalid redirect parameter", http.StatusBadRequest)
			return
		}

		f(rw, req)
	}
}

func validRedirectURI(uri string, rootDomains []string) bool {
	if uri == "" || len(rootDomains) == 0 {
		return false
	}
	redirectURL, err := url.Parse(uri)
	if err != nil || redirectURL.Host == "" {
		return false
	}
	for _, domain := range rootDomains {
		if domain == "" {
			return false
		}
		if strings.HasSuffix(redirectURL.Hostname(), domain) {
			return true
		}
	}
	return false
}

func validateSignature(f http.HandlerFunc, sharedKey string) http.HandlerFunc {
	return func(rw http.ResponseWriter, req *http.Request) {
		err := req.ParseForm()
		if err != nil {
			httputil.ErrorResponse(rw, req, err.Error(), http.StatusBadRequest)
			return
		}
		redirectURI := req.Form.Get("redirect_uri")
		sigVal := req.Form.Get("sig")
		timestamp := req.Form.Get("ts")
		if !validSignature(redirectURI, sigVal, timestamp, sharedKey) {
			httputil.ErrorResponse(rw, req, "Invalid redirect parameter", http.StatusBadRequest)
			return
		}

		f(rw, req)
	}
}

// validateSignature ensures the validity of the redirect url by comparing the hmac
// digest, and ensuring that the included timestamp is fresh
func validSignature(redirectURI, sigVal, timestamp, secret string) bool {
	if redirectURI == "" || sigVal == "" || timestamp == "" || secret == "" {
		return false
	}
	_, err := url.Parse(redirectURI)
	if err != nil {
		return false
	}
	requestSig, err := base64.URLEncoding.DecodeString(sigVal)
	if err != nil {
		return false
	}
	i, err := strconv.ParseInt(timestamp, 10, 64)
	if err != nil {
		return false
	}
	tm := time.Unix(i, 0)
	if time.Now().Sub(tm) > defaultSignatureValidityDuration {
		return false
	}
	localSig := redirectURLSignature(redirectURI, tm, secret)
	return hmac.Equal(requestSig, localSig)
}

// redirectURLSignature generates a hmac digest from a
// redirect url, a timestamp, and a secret.
func redirectURLSignature(rawRedirect string, timestamp time.Time, secret string) []byte {
	h := hmac.New(sha256.New, []byte(secret))
	h.Write([]byte(rawRedirect))
	h.Write([]byte(fmt.Sprint(timestamp.Unix())))
	return h.Sum(nil)
}
