package httputil

import "net/http"

const signedOutRedirectURICookieName = "_pomerium_signed_out_redirect_uri"

// GetSignedOutRedirectURICookie gets the redirect uri cookie for the signed-out page.
func GetSignedOutRedirectURICookie(w http.ResponseWriter, r *http.Request) (string, bool) {
	cookie, err := r.Cookie(signedOutRedirectURICookieName)
	if err != nil {
		return "", false
	}

	cookie.MaxAge = -1
	http.SetCookie(w, cookie)
	return cookie.Value, true
}

// SetSignedOutRedirectURICookie sets the redirect uri cookie for the signed-out page.
func SetSignedOutRedirectURICookie(w http.ResponseWriter, redirectURI string) {
	http.SetCookie(w, &http.Cookie{
		Name:   signedOutRedirectURICookieName,
		Value:  redirectURI,
		MaxAge: 5 * 60,
	})
}
