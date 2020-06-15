package authorize

import (
	"net/url"
	"regexp"
	"testing"

	envoy_service_auth_v2 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v2"
	"github.com/stretchr/testify/assert"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/encoding/jws"
	"github.com/pomerium/pomerium/internal/sessions"
)

func TestLoadSession(t *testing.T) {
	opts := *config.NewDefaultOptions()
	encoder, err := jws.NewHS256Signer(nil, "example.com")
	if !assert.NoError(t, err) {
		return
	}
	state := &sessions.State{
		Email: "bob@example.com",
	}
	rawjwt, err := encoder.Marshal(state)
	if !assert.NoError(t, err) {
		return
	}

	load := func(t *testing.T, hattrs *envoy_service_auth_v2.AttributeContext_HttpRequest) (*sessions.State, error) {
		req := getHTTPRequestFromCheckRequest(&envoy_service_auth_v2.CheckRequest{
			Attributes: &envoy_service_auth_v2.AttributeContext{
				Request: &envoy_service_auth_v2.AttributeContext_Request{
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

		hattrs := &envoy_service_auth_v2.AttributeContext_HttpRequest{
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
		if assert.NotNil(t, sess) {
			assert.Equal(t, "bob@example.com", sess.Email)
		}
	})
	t.Run("header", func(t *testing.T) {
		hattrs := &envoy_service_auth_v2.AttributeContext_HttpRequest{
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
		if assert.NotNil(t, sess) {
			assert.Equal(t, "bob@example.com", sess.Email)
		}
	})
	t.Run("query param", func(t *testing.T) {
		hattrs := &envoy_service_auth_v2.AttributeContext_HttpRequest{
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
		if assert.NotNil(t, sess) {
			assert.Equal(t, "bob@example.com", sess.Email)
		}
	})
}

func TestGetJWTClaimHeaders(t *testing.T) {
	options := config.NewDefaultOptions()
	options.JWTClaimsHeaders = []string{"email", "groups", "user"}
	encoder, err := jws.NewHS256Signer(nil, "example.com")
	if !assert.NoError(t, err) {
		return
	}
	state := &sessions.State{
		Email:  "bob@example.com",
		Groups: []string{"user", "wheel", "sudo"},
		User:   "bob",
	}
	rawjwt, err := encoder.Marshal(state)
	if !assert.NoError(t, err) {
		return
	}

	hdrs, err := getJWTClaimHeaders(*options, encoder, rawjwt)
	if !assert.NoError(t, err) {
		return
	}
	assert.Equal(t, map[string]string{
		"x-pomerium-claim-email":  "bob@example.com",
		"x-pomerium-claim-groups": "user,wheel,sudo",
		"x-pomerium-claim-user":   "bob",
	}, hdrs)
}
