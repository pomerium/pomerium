package authenticateflow

import (
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/encoding"
	"github.com/pomerium/pomerium/internal/encoding/mock"
	"github.com/pomerium/pomerium/internal/sessions"
	mstore "github.com/pomerium/pomerium/internal/sessions/mock"
	"github.com/pomerium/pomerium/internal/urlutil"
	"github.com/pomerium/pomerium/pkg/cryptutil"
)

func TestStatefulSignIn(t *testing.T) {
	opts := config.NewDefaultOptions()
	tests := []struct {
		name string

		host           string
		qp             map[string]string
		validSignature bool

		session   *sessions.State
		encoder   encoding.MarshalUnmarshaler
		saveError error

		wantErrorMsg        string
		wantRedirectBaseURL string
	}{
		{"good", "corp.example.example", map[string]string{urlutil.QueryRedirectURI: "https://dst.some.example/"}, true, &sessions.State{}, &mock.Encoder{}, nil, "", "https://dst.some.example/.pomerium/callback/"},
		{"good alternate port", "corp.example.example:8443", map[string]string{urlutil.QueryRedirectURI: "https://dst.some.example/"}, true, &sessions.State{}, &mock.Encoder{}, nil, "", "https://dst.some.example/.pomerium/callback/"},
		{"invalid signature", "corp.example.example", map[string]string{urlutil.QueryRedirectURI: "https://dst.some.example/"}, false, &sessions.State{}, &mock.Encoder{}, nil, "Bad Request:", ""},
		{"bad redirect uri query", "corp.example.example", map[string]string{urlutil.QueryRedirectURI: "^^^"}, true, &sessions.State{}, &mock.Encoder{}, nil, "Bad Request:", ""},
		{"bad marshal", "corp.example.example", map[string]string{urlutil.QueryRedirectURI: "https://dst.some.example/"}, true, &sessions.State{}, &mock.Encoder{MarshalError: errors.New("error")}, nil, "Bad Request: error", ""},
		{"good with different programmatic redirect", "corp.example.example", map[string]string{urlutil.QueryRedirectURI: "https://dst.some.example/", urlutil.QueryCallbackURI: "https://some.example"}, true, &sessions.State{}, &mock.Encoder{}, nil, "", "https://some.example"},
		{"encrypted encoder error", "corp.example.example", map[string]string{urlutil.QueryRedirectURI: "https://dst.some.example/", urlutil.QueryCallbackURI: "https://some.example"}, true, &sessions.State{}, &mock.Encoder{MarshalError: errors.New("error")}, nil, "Bad Request: error", ""},
		{"good with callback uri set", "corp.example.example", map[string]string{urlutil.QueryCallbackURI: "https://some.example/", urlutil.QueryRedirectURI: "https://dst.some.example/"}, true, &sessions.State{}, &mock.Encoder{}, nil, "", "https://some.example/"},
		{"bad callback uri set", "corp.example.example", map[string]string{urlutil.QueryCallbackURI: "^", urlutil.QueryRedirectURI: "https://dst.some.example/"}, true, &sessions.State{}, &mock.Encoder{}, nil, "Bad Request:", ""},
		{"good programmatic request", "corp.example.example", map[string]string{urlutil.QueryIsProgrammatic: "true", urlutil.QueryRedirectURI: "https://dst.some.example/"}, true, &sessions.State{}, &mock.Encoder{}, nil, "", "https://dst.some.example/.pomerium/callback/"},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			sessionStore := &mstore.Store{SaveError: tt.saveError}
			flow, err := NewStateful(&config.Config{Options: opts}, sessionStore)
			if err != nil {
				t.Fatal(err)
			}
			flow.sharedEncoder = tt.encoder

			uri := &url.URL{Scheme: "https", Host: tt.host}
			queryString := uri.Query()
			for k, v := range tt.qp {
				queryString.Set(k, v)
			}
			uri.RawQuery = queryString.Encode()
			if tt.validSignature {
				sharedKey, _ := opts.GetSharedKey()
				uri = urlutil.NewSignedURL(sharedKey, uri).Sign()
			}

			r := httptest.NewRequest(http.MethodGet, uri.String(), nil)
			r.Header.Set("Accept", "application/json")

			w := httptest.NewRecorder()
			err = flow.SignIn(w, r, tt.session)
			result := w.Result()
			if tt.wantErrorMsg == "" {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
				expectedStatus := "302 Found"
				if result.Status != expectedStatus {
					t.Errorf("wrong status code: got %v, want %v", result.Status, expectedStatus)
				}
				loc, err := url.Parse(result.Header.Get("Location"))
				if err != nil {
					t.Fatalf("couldn't parse redirect URL: %v", err)
				}
				loc.RawQuery = "" // ignore the query parameters
				if loc.String() != tt.wantRedirectBaseURL {
					t.Errorf("wrong redirect base URL: got %q, want %q",
						loc.String(), tt.wantRedirectBaseURL)
				}
			} else {
				if err == nil || !strings.Contains(err.Error(), tt.wantErrorMsg) {
					t.Errorf("expected error containing %q; got %v", tt.wantErrorMsg, err)
				}
			}
		})
	}
}

func TestStatefulAuthenticateSignInURL(t *testing.T) {
	opts := config.NewDefaultOptions()
	opts.AuthenticateURLString = "https://authenticate.example.com"
	key := cryptutil.NewKey()
	opts.SharedKey = base64.StdEncoding.EncodeToString(key)
	flow, err := NewStateful(&config.Config{Options: opts}, nil)
	require.NoError(t, err)

	t.Run("NilQueryParams", func(t *testing.T) {
		redirectURL := &url.URL{Scheme: "https", Host: "example.com"}
		u, err := flow.AuthenticateSignInURL(nil, nil, redirectURL, "fake-idp-id")
		assert.NoError(t, err)
		parsed, _ := url.Parse(u)
		assert.NoError(t, urlutil.NewSignedURL(key, parsed).Validate())
		assert.Equal(t, "https", parsed.Scheme)
		assert.Equal(t, "authenticate.example.com", parsed.Host)
		assert.Equal(t, "/.pomerium/sign_in", parsed.Path)
		q := parsed.Query()
		assert.Equal(t, "https://example.com", parsed.Query().Get("pomerium_redirect_uri"))
		assert.Equal(t, "fake-idp-id", q.Get("pomerium_idp_id"))
	})
	t.Run("ExtraQueryParams", func(t *testing.T) {
		redirectURL := &url.URL{Scheme: "https", Host: "example.com"}
		q := url.Values{}
		q.Set("foo", "bar")
		u, err := flow.AuthenticateSignInURL(nil, q, redirectURL, "fake-idp-id")
		assert.NoError(t, err)
		parsed, _ := url.Parse(u)
		assert.NoError(t, urlutil.NewSignedURL(key, parsed).Validate())
		assert.Equal(t, "https", parsed.Scheme)
		assert.Equal(t, "authenticate.example.com", parsed.Host)
		assert.Equal(t, "/.pomerium/sign_in", parsed.Path)
		q = parsed.Query()
		assert.Equal(t, "https://example.com", q.Get("pomerium_redirect_uri"))
		assert.Equal(t, "fake-idp-id", q.Get("pomerium_idp_id"))
		assert.Equal(t, "bar", q.Get("foo"))
	})
}

func TestStatefulGetIdentityProviderIDForURLValues(t *testing.T) {
	flow := Stateful{defaultIdentityProviderID: "default-id"}
	assert.Equal(t, "default-id", flow.GetIdentityProviderIDForURLValues(nil))
	q := url.Values{"pomerium_idp_id": []string{"idp-id"}}
	assert.Equal(t, "idp-id", flow.GetIdentityProviderIDForURLValues(q))
}

const goodEncryptionString = "KBEjQ9rnCxaAX-GOqetGw9ivEQURqts3zZ2mNGy0wnVa3SbtM399KlBq2nZ-9wM21FfsZX52er4jlmC7kPEKM3P7uZ41zR0zeys1-_74a5tQp-vsf1WXZfRsgVOuBcWPkMiWEoc379JFHxGDudp5VhU8B-dcQt4f3_PtLTHARkuH54io1Va2gNMq4Hiy8sQ1MPGCQeltH_JMzzdDpXdmdusWrXUvCGkba24muvAV06D8XRVJj6Iu9eK94qFnqcHc7wzziEbb8ADBues9dwbtb6jl8vMWz5rN6XvXqA5YpZv_MQZlsrO4oXFFQDevdgB84cX1tVbVu6qZvK_yQBZqzpOjWA9uIaoSENMytoXuWAlFO_sXjswfX8JTNdGwzB7qQRNPqxVG_sM_tzY3QhPm8zqwEzsXG5DokxZfVt2I5WJRUEovFDb4BnK9KFnnkEzLEdMudixVnXeGmTtycgJvoTeTCQRPfDYkcgJ7oKf4tGea-W7z5UAVa2RduJM9ZoM6YtJX7jgDm__PvvqcE0knJUF87XHBzdcOjoDF-CUze9xDJgNBlvPbJqVshKrwoqSYpePSDH9GUCNKxGequW3Ma8GvlFfhwd0rK6IZG-XWkyk0XSWQIGkDSjAvhB1wsOusCCguDjbpVZpaW5MMyTkmx68pl6qlIKT5UCcrVPl4ix5ZEj91mUDF0O1t04haD7VZuLVFXVGmqtFrBKI76sdYN-zkokaa1_chPRTyqMQFlqu_8LD6-RiK3UccGM-dEmnX72i91NP9F9OK0WJr9Cheup1C_P0mjqAO4Cb8oIHm0Oxz_mRqv5QbTGJtb3xwPLPuVjVCiE4gGBcuU2ixpSVf5HUF7y1KicVMCKiX9ATCBtg8sTdQZQnPEtHcHHAvdsnDVwev1LGfqA-Gdvg="

func TestStatefulCallback(t *testing.T) {
	opts := config.NewDefaultOptions()
	opts.SharedKey = "80ldlrU2d7w+wVpKNfevk6fmb8otEx6CqOfshj2LwhQ="
	tests := []struct {
		name string

		qp             map[string]string
		validSignature bool
		cipher         encoding.MarshalUnmarshaler
		sessionStore   sessions.SessionStore

		wantErrorMsg string
	}{
		{
			"good",
			map[string]string{urlutil.QueryCallbackURI: "ok", urlutil.QuerySessionEncrypted: goodEncryptionString},
			true,
			&mock.Encoder{MarshalResponse: []byte("x")},
			&mstore.Store{Session: &sessions.State{}},
			"",
		},
		{
			"good programmatic",
			map[string]string{urlutil.QueryIsProgrammatic: "true", urlutil.QueryCallbackURI: "ok", urlutil.QuerySessionEncrypted: goodEncryptionString},
			true,
			&mock.Encoder{MarshalResponse: []byte("x")},
			&mstore.Store{Session: &sessions.State{}},
			"",
		},
		{
			"invalid signature",
			map[string]string{urlutil.QueryCallbackURI: "ok", urlutil.QuerySessionEncrypted: goodEncryptionString},
			false,
			&mock.Encoder{MarshalResponse: []byte("x")},
			&mstore.Store{Session: &sessions.State{}},
			"Bad Request:",
		},
		{
			"bad decrypt",
			map[string]string{urlutil.QuerySessionEncrypted: "KBEjQ9rnCxaAX-GOqexGw9ivEQURqts3zZ2mNGy0wnVa3SbtM399KlBq2nZ-9wM21FfsZX52er4jlmC7kPEKM3P7uZ41zR0zeys1-_74a5tQp-vsf1WXZfRsgVOuBcWPkMiWEoc379JFHxGDudp5VhU8B-dcQt4f3_PtLTHARkuH54io1Va2gNMq4Hiy8sQ1MPGCQeltH_JMzzdDpXdmdusWrXUvCGkba24muvAV06D8XRVJj6Iu9eK94qFnqcHc7wzziEbb8ADBues9dwbtb6jl8vMWz5rN6XvXqA5YpZv_MQZlsrO4oXFFQDevdgB84cX1tVbVu6qZvK_yQBZqzpOjWA9uIaoSENMytoXuWAlFO_sXjswfX8JTNdGwzB7qQRNPqxVG_sM_tzY3QhPm8zqwEzsXG5DokxZfVt2I5WJRUEovFDb4BnK9KFnnkEzLEdMudixVnXeGmTtycgJvoTeTCQRPfDYkcgJ7oKf4tGea-W7z5UAVa2RduJM9ZoM6YtJX7jgDm__PvvqcE0knJUF87XHBzdcOjoDF-CUze9xDJgNBlvPbJqVshKrwoqSYpePSDH9GUCNKxGequW3Ma8GvlFfhwd0rK6IZG-XWkyk0XSWQIGkDSjAvhB1wsOusCCguDjbpVZpaW5MMyTkmx68pl6qlIKT5UCcrVPl4ix5ZEj91mUDF0O1t04haD7VZuLVFXVGmqtFrBKI76sdYN-zkokaa1_chPRTyqMQFlqu_8LD6-RiK3UccGM-dEmnX72i91NP9F9OK0WJr9Cheup1C_P0mjqAO4Cb8oIHm0Oxz_mRqv5QbTGJtb3xwPLPuVjVCiE4gGBcuU2ixpSVf5HUF7y1KicVMCKiX9ATCBtg8sTdQZQnPEtHcHHAvdsnDVwev1LGfqA-Gdvg="},
			true,
			&mock.Encoder{MarshalResponse: []byte("x")},
			&mstore.Store{Session: &sessions.State{}},
			"proxy: callback token decrypt error:",
		},
		{
			"bad save session",
			map[string]string{urlutil.QuerySessionEncrypted: goodEncryptionString},
			true,
			&mock.Encoder{MarshalResponse: []byte("x")},
			&mstore.Store{SaveError: errors.New("hi")},
			"Internal Server Error: proxy: error saving session state:",
		},
		{
			"bad base64",
			map[string]string{urlutil.QuerySessionEncrypted: "^"},
			true,
			&mock.Encoder{MarshalResponse: []byte("x")},
			&mstore.Store{Session: &sessions.State{}},
			"proxy: malfromed callback token:",
		},
		{
			"malformed redirect",
			nil,
			true,
			&mock.Encoder{},
			&mstore.Store{Session: &sessions.State{}},
			"Bad Request:",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			flow, err := NewStateful(&config.Config{Options: opts}, tt.sessionStore)
			if err != nil {
				t.Fatal(err)
			}
			flow.sharedEncoder = tt.cipher
			redirectURI := &url.URL{Scheme: "http", Host: "example.com", Path: "/"}
			queryString := redirectURI.Query()
			for k, v := range tt.qp {
				queryString.Set(k, v)
			}
			redirectURI.RawQuery = queryString.Encode()

			uri := &url.URL{Scheme: "https", Host: "example.com", Path: "/"}
			if tt.qp != nil {
				qu := uri.Query()
				for k, v := range tt.qp {
					qu.Set(k, v)
				}
				qu.Set(urlutil.QueryRedirectURI, redirectURI.String())
				uri.RawQuery = qu.Encode()
			}
			if tt.validSignature {
				sharedKey, _ := opts.GetSharedKey()
				uri = urlutil.NewSignedURL(sharedKey, uri).Sign()
			}

			r := httptest.NewRequest(http.MethodGet, uri.String(), nil)
			//fmt.Println(uri.String())
			r.Host = r.URL.Host

			r.Header.Set("Accept", "application/json")

			w := httptest.NewRecorder()
			err = flow.Callback(w, r)
			if tt.wantErrorMsg == "" {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
			} else {
				if err == nil || !strings.Contains(err.Error(), tt.wantErrorMsg) {
					t.Errorf("expected error containing %q; got %v", tt.wantErrorMsg, err)
				}
			}

			// XXX: assert redirect URL
		})
	}
}
