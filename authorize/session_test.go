package authorize

import (
	"net/url"
	"regexp"
	"testing"

	envoy_service_auth_v3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	"github.com/stretchr/testify/assert"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/encoding/jws"
	"github.com/pomerium/pomerium/internal/sessions"
)

func TestLoadSession(t *testing.T) {
	opts := config.NewDefaultOptions()
	encoder, err := jws.NewHS256Signer(nil)
	if !assert.NoError(t, err) {
		return
	}
	state := &sessions.State{ID: "xyz", Version: "v1"}
	rawjwt, err := encoder.Marshal(state)
	if !assert.NoError(t, err) {
		return
	}

	load := func(t *testing.T, hattrs *envoy_service_auth_v3.AttributeContext_HttpRequest) (*sessions.State, error) {
		req := getHTTPRequestFromCheckRequest(&envoy_service_auth_v3.CheckRequest{
			Attributes: &envoy_service_auth_v3.AttributeContext{
				Request: &envoy_service_auth_v3.AttributeContext_Request{
					Http: hattrs,
				},
			},
		})
		raw, err := loadRawSession(req, opts, encoder)
		if err != nil {
			return nil, err
		}
		var state sessions.State
		err = encoder.Unmarshal(raw, &state)
		if err != nil {
			return nil, err
		}
		return &state, nil
	}

	t.Run("cookie", func(t *testing.T) {
		cookieStore, err := getCookieStore(opts, encoder)
		if !assert.NoError(t, err) {
			return
		}
		hdrs, err := getJWTSetCookieHeaders(cookieStore, rawjwt)
		if !assert.NoError(t, err) {
			return
		}
		cookie := regexp.MustCompile(`^([^;]+)(;.*)?$`).ReplaceAllString(hdrs["Set-Cookie"], "$1")

		hattrs := &envoy_service_auth_v3.AttributeContext_HttpRequest{
			Id:     "req-1",
			Method: "GET",
			Headers: map[string]string{
				"Cookie": cookie,
			},
			Path:   "/hello/world",
			Host:   "example.com",
			Scheme: "https",
		}
		sess, err := load(t, hattrs)
		assert.NoError(t, err)
		assert.NotNil(t, sess)
	})
	t.Run("header", func(t *testing.T) {
		hattrs := &envoy_service_auth_v3.AttributeContext_HttpRequest{
			Id:     "req-1",
			Method: "GET",
			Headers: map[string]string{
				"Authorization": "Pomerium " + string(rawjwt),
			},
			Path:   "/hello/world",
			Host:   "example.com",
			Scheme: "https",
		}
		sess, err := load(t, hattrs)
		assert.NoError(t, err)
		assert.NotNil(t, sess)
	})
	t.Run("query param", func(t *testing.T) {
		hattrs := &envoy_service_auth_v3.AttributeContext_HttpRequest{
			Id:     "req-1",
			Method: "GET",
			Path: "/hello/world?" + url.Values{
				"pomerium_session": []string{string(rawjwt)},
			}.Encode(),
			Host:   "example.com",
			Scheme: "https",
		}
		sess, err := load(t, hattrs)
		assert.NoError(t, err)
		assert.NotNil(t, sess)
	})
}
