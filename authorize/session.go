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

func loadSession(req *http.Request, options config.Options, encoder encoding.MarshalUnmarshaler) ([]byte, error) {
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

func getCookieStore(options config.Options, encoder encoding.MarshalUnmarshaler) (sessions.SessionStore, error) {
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

func getJWTClaimHeaders(options config.Options, encoder encoding.MarshalUnmarshaler, rawjwt []byte) (map[string]string, error) {
	var claims map[string]jwtClaim
	err := encoder.Unmarshal(rawjwt, &claims)
	if err != nil {
		return nil, err
	}

	hdrs := make(map[string]string)
	for _, name := range options.JWTClaimsHeaders {
		if claim, ok := claims[name]; ok {
			hdrs["x-pomerium-claim-"+name] = strings.Join(claim, ",")
		}
	}
	return hdrs, nil
}

type jwtClaim []string

func (claim *jwtClaim) UnmarshalJSON(bs []byte) error {
	var raw interface{}
	err := json.Unmarshal(bs, &raw)
	if err != nil {
		return err
	}
	switch obj := raw.(type) {
	case []interface{}:
		for _, el := range obj {
			*claim = append(*claim, fmt.Sprint(el))
		}
	default:
		*claim = append(*claim, fmt.Sprint(obj))
	}
	return nil
}
