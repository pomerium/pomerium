package identity

import (
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/securecookie"
)

var browserIDExpiration = 24 * time.Hour * 365

func browserIDCookieName(name string) string {
	return name + "_browser_id"
}

type BrowserIDOptions struct {
	CookieName string
	AuthKey    []byte
	BrowserID  string
	SameSite   http.SameSite
}

func EnsureBrowserIDCookie(
	r *http.Request,
	w http.ResponseWriter,
	genOptions BrowserIDOptions,
) (string, error) {
	browserID, err := getBrowserIDFromCookie(genOptions.CookieName, genOptions.AuthKey, r)
	if err == nil {
		return browserID, nil
	}
	cookie, err := GenerateBrowserIDCookie(genOptions)
	if err != nil {
		return "", err
	}
	http.SetCookie(w, cookie)
	return genOptions.BrowserID, nil
}

func GenerateBrowserIDCookie(genOptions BrowserIDOptions) (*http.Cookie, error) {
	sc := securecookie.New(genOptions.AuthKey, nil)
	sc.SetSerializer(securecookie.JSONEncoder{})
	encoded, err := sc.Encode(genOptions.CookieName+"_browser_id", genOptions.BrowserID)
	if err != nil {
		return nil, err
	}
	return &http.Cookie{
		Name:     browserIDCookieName(genOptions.CookieName),
		Value:    encoded,
		HttpOnly: true,
		Secure:   true,
		SameSite: genOptions.SameSite,
		Path:     "/",
		MaxAge:   int(browserIDExpiration.Seconds()),
		Expires:  time.Now().Add(browserIDExpiration),
	}, nil
}

func getBrowserIDFromCookie(name string, authKey []byte, r *http.Request) (string, error) {
	sc := securecookie.New(authKey, nil)
	sc.SetSerializer(securecookie.JSONEncoder{})
	cName := browserIDCookieName(name)
	cookie, err := r.Cookie(cName)
	if err != nil {
		return "", err
	}

	var browserID string
	if err := sc.Decode(cName, cookie.Value, &browserID); err != nil {
		return "", err
	}

	if _, err := uuid.Parse(browserID); err != nil {
		return "", err
	}

	return browserID, nil
}
