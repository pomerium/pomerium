package authorize

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/encoding"
	"github.com/pomerium/pomerium/internal/httputil"
	"github.com/pomerium/pomerium/internal/sessions"
	"github.com/pomerium/pomerium/internal/sessions/cookie"
	"github.com/pomerium/pomerium/internal/sessions/header"
	"github.com/pomerium/pomerium/internal/sessions/queryparam"
	"github.com/pomerium/pomerium/internal/urlutil"
)

func loadRawSession(req *http.Request, options *config.Options, encoder encoding.MarshalUnmarshaler) ([]byte, error) {
	var loaders []sessions.SessionLoader
	cookieStore, err := getCookieStore(options, encoder)
	if err != nil {
		return nil, err
	}
	loaders = append(loaders,
		cookieStore,
		header.NewStore(encoder, httputil.AuthorizationTypePomerium),
		queryparam.NewStore(encoder, urlutil.QuerySession),
	)

	for _, loader := range loaders {
		sess, err := loader.LoadSession(req)
		if err != nil && !errors.Is(err, sessions.ErrNoSessionFound) {
			return nil, err
		} else if err == nil {
			return []byte(sess), nil
		}
	}

	return nil, sessions.ErrNoSessionFound
}

func loadSession(encoder encoding.MarshalUnmarshaler, rawJWT []byte) (*sessions.State, error) {
	var s sessions.State
	err := encoder.Unmarshal(rawJWT, &s)
	if err != nil {
		return nil, err
	}
	return &s, nil
}

func getCookieStore(options *config.Options, encoder encoding.MarshalUnmarshaler) (sessions.SessionStore, error) {
	cookieOptions := &cookie.Options{
		Name:     options.CookieName,
		Domain:   options.CookieDomain,
		Secure:   options.CookieSecure,
		HTTPOnly: options.CookieHTTPOnly,
		Expire:   options.CookieExpire,
	}
	cookieStore, err := cookie.NewStore(cookieOptions, encoder)
	if err != nil {
		return nil, err
	}
	return cookieStore, nil
}

func getJWTSetCookieHeaders(cookieStore sessions.SessionStore, rawjwt []byte) (map[string]string, error) {
	recorder := httptest.NewRecorder()
	err := cookieStore.SaveSession(recorder, nil /* unused by cookie store */, string(rawjwt))
	if err != nil {
		return nil, fmt.Errorf("authorize: error saving cookie: %w", err)
	}

	res := recorder.Result()
	res.Body.Close()

	hdrs := make(map[string]string)
	for k, vs := range res.Header {
		for _, v := range vs {
			hdrs[k] = v
		}
	}
	return hdrs, nil
}

func (a *Authorize) getJWTClaimHeaders(options *config.Options, signedJWT string) (map[string]string, error) {
	if len(signedJWT) == 0 {
		return make(map[string]string), nil
	}

	var claims map[string]interface{}
	payload, err := a.pe.ParseSignedJWT(signedJWT)
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, err
	}

	hdrs := make(map[string]string)
	for _, name := range options.JWTClaimsHeaders {
		if claim, ok := claims[name]; ok {
			switch value := claim.(type) {
			case string:
				hdrs["x-pomerium-claim-"+name] = value
			case []interface{}:
				hdrs["x-pomerium-claim-"+name] = strings.Join(toSliceStrings(value), ",")
			}
		}
	}
	return hdrs, nil
}

func toSliceStrings(sliceIfaces []interface{}) []string {
	sliceStrings := make([]string, 0, len(sliceIfaces))
	for _, e := range sliceIfaces {
		sliceStrings = append(sliceStrings, fmt.Sprint(e))
	}
	return sliceStrings
}
