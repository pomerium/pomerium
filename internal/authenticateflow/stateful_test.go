package authenticateflow

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v3/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/trace"
	"go.uber.org/mock/gomock"
	"golang.org/x/oauth2"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/encoding"
	"github.com/pomerium/pomerium/internal/encoding/mock"
	"github.com/pomerium/pomerium/internal/sessions"
	mstore "github.com/pomerium/pomerium/internal/sessions/mock"
	"github.com/pomerium/pomerium/internal/testutil"
	"github.com/pomerium/pomerium/internal/urlutil"
	"github.com/pomerium/pomerium/pkg/cryptutil"
	"github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/grpc/databroker/mock_databroker"
	"github.com/pomerium/pomerium/pkg/grpc/session"
	"github.com/pomerium/pomerium/pkg/grpc/user"
	"github.com/pomerium/pomerium/pkg/identity"
	"github.com/pomerium/pomerium/pkg/protoutil"
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
		t.Run(tt.name, func(t *testing.T) {
			sessionStore := &mstore.Store{SaveError: tt.saveError}
			flow, err := NewStateful(t.Context(), trace.NewNoopTracerProvider(), &config.Config{Options: opts}, sessionStore)
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
	flow, err := NewStateful(t.Context(), trace.NewNoopTracerProvider(), &config.Config{Options: opts}, nil)
	require.NoError(t, err)

	t.Run("NilQueryParams", func(t *testing.T) {
		redirectURL := &url.URL{Scheme: "https", Host: "example.com"}
		u, err := flow.AuthenticateSignInURL(t.Context(), nil, redirectURL, "fake-idp-id", nil)
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
		u, err := flow.AuthenticateSignInURL(t.Context(), q, redirectURL, "fake-idp-id", nil)
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
	t.Run("AdditionalHosts", func(t *testing.T) {
		redirectURL := &url.URL{Scheme: "https", Host: "example.com"}
		additionalHosts := []string{"foo.example.com", "bar.example.com:1234"}
		u, err := flow.AuthenticateSignInURL(t.Context(), nil, redirectURL, "fake-idp-id", additionalHosts)
		assert.NoError(t, err)
		parsed, _ := url.Parse(u)
		assert.NoError(t, urlutil.NewSignedURL(key, parsed).Validate())
		assert.Equal(t, "https", parsed.Scheme)
		assert.Equal(t, "authenticate.example.com", parsed.Host)
		assert.Equal(t, "/.pomerium/sign_in", parsed.Path)
		q := parsed.Query()
		assert.Equal(t, "https://example.com", parsed.Query().Get("pomerium_redirect_uri"))
		assert.Equal(t, "fake-idp-id", q.Get("pomerium_idp_id"))
		assert.Equal(t, "foo.example.com,bar.example.com:1234", q.Get("pomerium_additional_hosts"))
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
			flow, err := NewStateful(t.Context(), trace.NewNoopTracerProvider(), &config.Config{Options: opts}, tt.sessionStore)
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
			r.Host = r.URL.Host

			r.Header.Set("Accept", "application/json")

			w := httptest.NewRecorder()
			err = flow.Callback(w, r)
			if tt.wantErrorMsg == "" {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
				location, _ := url.Parse(w.Result().Header.Get("Location"))
				assert.Equal(t, "example.com", location.Host)
				assert.Equal(t, "/", location.Path)
				assert.Equal(t, "ok", location.Query().Get("pomerium_callback_uri"))
			} else {
				if err == nil || !strings.Contains(err.Error(), tt.wantErrorMsg) {
					t.Errorf("expected error containing %q; got %v", tt.wantErrorMsg, err)
				}
			}
		})
	}
}

func TestStatefulCallback_AdditionalHosts(t *testing.T) {
	opts := config.NewDefaultOptions()
	opts.SharedKey = "80ldlrU2d7w+wVpKNfevk6fmb8otEx6CqOfshj2LwhQ="
	sharedKey, _ := opts.GetSharedKey()

	flow, err := NewStateful(
		t.Context(),
		trace.NewNoopTracerProvider(),
		&config.Config{Options: opts},
		&mstore.Store{Session: &sessions.State{}},
	)
	require.NoError(t, err)

	redirectURI := "https://route.example.com/"
	callbackURI := &url.URL{
		Scheme: "https",
		Host:   "route.example.com",
		Path:   "/.pomerium/callback",
		RawQuery: url.Values{
			urlutil.QuerySessionEncrypted: []string{goodEncryptionString},
			urlutil.QueryRedirectURI:      []string{redirectURI},
			urlutil.QueryAdditionalHosts:  []string{"foo.example.com,bar.example.com"},
		}.Encode(),
	}
	signedCallbackURI := urlutil.NewSignedURL(sharedKey, callbackURI)

	doCallback := func(uri string) *http.Response {
		t.Helper()
		r := httptest.NewRequest(http.MethodGet, uri, nil)
		r.Host = r.URL.Host

		w := httptest.NewRecorder()
		err = flow.Callback(w, r)
		require.NoError(t, err)
		return w.Result()
	}

	// Callback() should serve redirects to the additional hosts before the final redirect URI.
	res := doCallback(signedCallbackURI.String())
	location, _ := url.Parse(res.Header.Get("Location"))
	assert.Equal(t, "foo.example.com", location.Host)
	assert.Equal(t, "/.pomerium/callback/", location.Path)

	res = doCallback(location.String())
	location, _ = url.Parse(res.Header.Get("Location"))
	assert.Equal(t, "bar.example.com", location.Host)
	assert.Equal(t, "/.pomerium/callback/", location.Path)

	res = doCallback(location.String())
	location, _ = url.Parse(res.Header.Get("Location"))
	assert.Equal(t, "route.example.com", location.Host)
	assert.Equal(t, "/", location.Path)
}

func TestStatefulRevokeSession(t *testing.T) {
	opts := config.NewDefaultOptions()
	flow, err := NewStateful(t.Context(), trace.NewNoopTracerProvider(), &config.Config{Options: opts}, nil)
	require.NoError(t, err)

	ctrl := gomock.NewController(t)
	client := mock_databroker.NewMockDataBrokerServiceClient(ctrl)
	flow.dataBrokerClient = client

	// Exercise the happy path (no errors): calling RevokeSession() should
	// fetch and delete a session record from the databroker and make a request
	// to the identity provider to revoke the corresponding OAuth2 token.

	ctx := t.Context()
	authenticator := &mockAuthenticator{}
	sessionState := &sessions.State{ID: "session-id"}
	tokenExpiry := time.Date(2024, 1, 1, 12, 0, 0, 0, time.UTC)

	client.EXPECT().Get(ctx, protoEqualMatcher{
		&databroker.GetRequest{
			Type: "type.googleapis.com/session.Session",
			Id:   "session-id",
		},
	}).Return(&databroker.GetResponse{
		Record: &databroker.Record{
			Version: 123456,
			Type:    "type.googleapis.com/session.Session",
			Id:      "session-id",
			Data: protoutil.NewAny(&session.Session{
				Id:     "session-id",
				UserId: "user-id",
				IdToken: &session.IDToken{
					Raw: "[raw-id-token]",
				},
				OauthToken: &session.OAuthToken{
					AccessToken:  "[oauth-access-token]",
					TokenType:    "Bearer",
					RefreshToken: "[oauth-refresh-token]",
					ExpiresAt:    timestamppb.New(tokenExpiry),
				},
			}),
		},
	}, nil)

	client.EXPECT().Put(ctx, gomock.Any()).DoAndReturn(
		func(_ context.Context, r *databroker.PutRequest, _ ...grpc.CallOption) (*databroker.PutResponse, error) {
			require.Len(t, r.Records, 1)
			record := r.GetRecord()
			assert.Equal(t, "type.googleapis.com/session.Session", record.Type)
			assert.Equal(t, "session-id", record.Id)
			assert.Equal(t, uint64(123456), record.Version)

			// The session record received in this PutRequest should have a
			// DeletedAt timestamp, as well as the same session ID and user ID
			// as was returned in the previous GetResponse.
			assert.NotNil(t, record.DeletedAt)
			var s session.Session
			record.GetData().UnmarshalTo(&s)
			assert.Equal(t, "session-id", s.Id)
			assert.Equal(t, "user-id", s.UserId)
			return nil, nil
		})

	idToken := flow.RevokeSession(ctx, nil, authenticator, sessionState)

	assert.Equal(t, "[raw-id-token]", idToken)
	assert.Equal(t, &oauth2.Token{
		AccessToken:  "[oauth-access-token]",
		TokenType:    "Bearer",
		RefreshToken: "[oauth-refresh-token]",
		Expiry:       tokenExpiry,
	}, authenticator.revokedToken)
}

func TestPersistSession(t *testing.T) {
	timeNow = func() time.Time { return time.Unix(1721965100, 0) }
	t.Cleanup(func() { timeNow = time.Now })

	opts := config.NewDefaultOptions()
	opts.CookieExpire = 4 * time.Hour
	flow, err := NewStateful(t.Context(), trace.NewNoopTracerProvider(), &config.Config{Options: opts}, nil)
	require.NoError(t, err)

	ctrl := gomock.NewController(t)
	client := mock_databroker.NewMockDataBrokerServiceClient(ctrl)
	flow.dataBrokerClient = client

	ctx := t.Context()

	client.EXPECT().Get(ctx, protoEqualMatcher{
		&databroker.GetRequest{
			Type: "type.googleapis.com/user.User",
			Id:   "user-id",
		},
	}).Return(&databroker.GetResponse{}, nil)

	// PersistSession should copy data from the sessions.State,
	// identity.SessionClaims, and oauth2.Token into a Session and User record.
	sessionState := &sessions.State{
		ID:       "session-id",
		Subject:  "user-id",
		Audience: jwt.Audience{"route.example.com"},
	}
	claims := identity.SessionClaims{
		Claims: map[string]any{
			"name":  "John Doe",
			"email": "john.doe@example.com",
		},
		RawIDToken: "e30." + base64.RawURLEncoding.EncodeToString([]byte(`{
			"iss": "https://issuer.example.com",
			"sub": "id-token-user-id",
			"iat": 1721965070,
			"exp": 1721965670
		}`)) + ".fake-signature",
	}
	accessToken := &oauth2.Token{
		AccessToken:  "access-token",
		RefreshToken: "refresh-token",
		Expiry:       time.Unix(1721965190, 0),
	}

	expectedClaims := map[string]*structpb.ListValue{
		"name":  {Values: []*structpb.Value{structpb.NewStringValue("John Doe")}},
		"email": {Values: []*structpb.Value{structpb.NewStringValue("john.doe@example.com")}},
	}

	client.EXPECT().Put(ctx, gomock.Any()).DoAndReturn(
		func(_ context.Context, r *databroker.PutRequest, _ ...grpc.CallOption) (*databroker.PutResponse, error) {
			require.Len(t, r.Records, 1)
			record := r.GetRecord()
			assert.Equal(t, "type.googleapis.com/user.User", record.Type)
			assert.Equal(t, "user-id", record.Id)
			assert.Nil(t, record.DeletedAt)

			// Verify that claims data is populated into the User record.
			var u user.User
			record.GetData().UnmarshalTo(&u)
			assert.Equal(t, "user-id", u.Id)
			assert.Equal(t, expectedClaims, u.Claims)

			// A real response would include the record, but here we can skip it as it isn't used.
			return &databroker.PutResponse{}, nil
		})

	client.EXPECT().Put(ctx, gomock.Any()).DoAndReturn(
		func(_ context.Context, r *databroker.PutRequest, _ ...grpc.CallOption) (*databroker.PutResponse, error) {
			require.Len(t, r.Records, 1)
			record := r.GetRecord()
			assert.Equal(t, "type.googleapis.com/session.Session", record.Type)
			assert.Equal(t, "session-id", record.Id)
			assert.Nil(t, record.DeletedAt)

			var s session.Session
			record.GetData().UnmarshalTo(&s)
			testutil.AssertProtoEqual(t, &session.Session{
				Id:         "session-id",
				UserId:     "user-id",
				IssuedAt:   timestamppb.New(time.Unix(1721965100, 0)),
				AccessedAt: timestamppb.New(time.Unix(1721965100, 0)),
				ExpiresAt:  timestamppb.New(time.Unix(1721979500, 0)),
				Audience:   []string{"route.example.com"},
				Claims:     expectedClaims,
				IdToken: &session.IDToken{
					Issuer:    "https://issuer.example.com",
					Subject:   "id-token-user-id",
					IssuedAt:  &timestamppb.Timestamp{Seconds: 1721965070},
					ExpiresAt: &timestamppb.Timestamp{Seconds: 1721965670},
					Raw:       claims.RawIDToken,
				},
				OauthToken: &session.OAuthToken{
					AccessToken:  "access-token",
					RefreshToken: "refresh-token",
					ExpiresAt:    &timestamppb.Timestamp{Seconds: 1721965190},
				},
			}, &s)

			return &databroker.PutResponse{
				ServerVersion: 2222,
				Records: []*databroker.Record{{
					Version: 1111,
					Type:    "type.googleapis.com/session.Session",
					Id:      "session-id",
					Data:    protoutil.NewAny(&s),
				}},
			}, nil
		})

	err = flow.PersistSession(ctx, nil, sessionState, claims, accessToken)
	assert.NoError(t, err)
	assert.Equal(t, uint64(1111), sessionState.DatabrokerRecordVersion)
	assert.Equal(t, uint64(2222), sessionState.DatabrokerServerVersion)
}

// protoEqualMatcher implements gomock.Matcher using proto.Equal.
// TODO: move this to a testutil package?
type protoEqualMatcher struct {
	expected proto.Message
}

func (m protoEqualMatcher) Matches(x any) bool {
	p, ok := x.(proto.Message)
	if !ok {
		return false
	}
	return proto.Equal(m.expected, p)
}

func (m protoEqualMatcher) String() string {
	return fmt.Sprintf("is equal to %v (%T)", m.expected, m.expected)
}

type mockAuthenticator struct {
	identity.Authenticator

	revokedToken *oauth2.Token
	revokeError  error
}

func (a *mockAuthenticator) Revoke(_ context.Context, token *oauth2.Token) error {
	a.revokedToken = token
	return a.revokeError
}
