package authorize

import (
	"net/url"
	"regexp"
	"testing"

	envoy_service_auth_v2 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pomerium/pomerium/authorize/evaluator"
	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/directory"
	"github.com/pomerium/pomerium/internal/encoding/jws"
	"github.com/pomerium/pomerium/internal/sessions"
	"github.com/pomerium/pomerium/pkg/grpc/session"
	"github.com/pomerium/pomerium/pkg/grpc/user"
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
		assert.NotNil(t, sess)
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
		assert.NotNil(t, sess)
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
		assert.NotNil(t, sess)
	})
}

func TestAuthorize_getJWTClaimHeaders(t *testing.T) {
	opt := &config.Options{
		AuthenticateURL: mustParseURL("https://authenticate.example.com"),
		Policies: []config.Policy{{
			Source: &config.StringURL{URL: &url.URL{Host: "example.com"}},
			SubPolicies: []config.SubPolicy{{
				Rego: []string{"allow = true"},
			}},
		}},
	}
	a := &Authorize{currentOptions: config.NewAtomicOptions(), state: newAtomicAuthorizeState(new(authorizeState))}
	encoder, _ := jws.NewHS256Signer([]byte{0, 0, 0, 0})
	a.state.Load().encoder = encoder
	a.currentOptions.Store(opt)
	a.store = evaluator.NewStoreFromProtos(
		&session.Session{
			Id:     "SESSION_ID",
			UserId: "USER_ID",
		},
		&user.User{
			Id:    "USER_ID",
			Name:  "foo",
			Email: "foo@example.com",
		},
		&directory.User{
			Id:       "USER_ID",
			GroupIds: []string{"admin_id", "test_id"},
		},
		&directory.Group{
			Id:   "admin_id",
			Name: "admin",
		},
		&directory.Group{
			Id:   "test_id",
			Name: "test",
		},
	)
	pe, err := newPolicyEvaluator(opt, a.store)
	require.NoError(t, err)
	a.state.Load().evaluator = pe
	signedJWT, _ := pe.SignedJWT(pe.JWTPayload(&evaluator.Request{
		HTTP: evaluator.RequestHTTP{URL: "https://example.com"},
		Session: evaluator.RequestSession{
			ID: "SESSION_ID",
		},
	}))

	tests := []struct {
		name            string
		signedJWT       string
		jwtHeaders      []string
		expectedHeaders map[string]string
	}{
		{"good with email", signedJWT, []string{"email"}, map[string]string{"x-pomerium-claim-email": "foo@example.com"}},
		{"good with groups", signedJWT, []string{"groups"}, map[string]string{"x-pomerium-claim-groups": "admin_id,test_id,admin,test"}},
		{"empty signed JWT", "", nil, make(map[string]string)},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			opt.JWTClaimsHeaders = tc.jwtHeaders
			gotHeaders, err := a.getJWTClaimHeaders(opt, tc.signedJWT)
			require.NoError(t, err)
			assert.Equal(t, tc.expectedHeaders, gotHeaders)
		})
	}
}
