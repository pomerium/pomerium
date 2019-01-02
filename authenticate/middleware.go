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
	redirectURL, err := url.Parse(uri)
	if uri == "" || err != nil || redirectURL.Host == "" {
		return false
	}
	for _, domain := range rootDomains {
		if strings.HasSuffix(redirectURL.Hostname(), domain) {
			return true
		}
	}
	return false
}

func validateSignature(f http.HandlerFunc, proxyClientSecret string) http.HandlerFunc {
	return func(rw http.ResponseWriter, req *http.Request) {
		err := req.ParseForm()
		if err != nil {
			httputil.ErrorResponse(rw, req, err.Error(), http.StatusBadRequest)
			return
		}
		redirectURI := req.Form.Get("redirect_uri")
		sigVal := req.Form.Get("sig")
		timestamp := req.Form.Get("ts")
		if !validSignature(redirectURI, sigVal, timestamp, proxyClientSecret) {
			httputil.ErrorResponse(rw, req, "Invalid redirect parameter", http.StatusBadRequest)
			return
		}

		f(rw, req)
	}
}

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
	ttl := 5 * time.Minute
	if time.Now().Sub(tm) > ttl {
		return false
	}
	localSig := redirectURLSignature(redirectURI, tm, secret)
	return hmac.Equal(requestSig, localSig)
}

func redirectURLSignature(rawRedirect string, timestamp time.Time, secret string) []byte {
	h := hmac.New(sha256.New, []byte(secret))
	h.Write([]byte(rawRedirect))
	h.Write([]byte(fmt.Sprint(timestamp.Unix())))
	return h.Sum(nil)
}
