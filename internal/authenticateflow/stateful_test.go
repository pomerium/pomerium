package authenticateflow

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
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
	"go.opentelemetry.io/otel/trace/noop"
	"go.uber.org/mock/gomock"
	"golang.org/x/oauth2"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/encoding"
	"github.com/pomerium/pomerium/internal/encoding/mock"
	"github.com/pomerium/pomerium/internal/httputil"
	"github.com/pomerium/pomerium/internal/sessions"
	mstore "github.com/pomerium/pomerium/internal/sessions/mock"
	"github.com/pomerium/pomerium/internal/testutil"
	"github.com/pomerium/pomerium/internal/testutil/matchers"
	"github.com/pomerium/pomerium/internal/urlutil"
	"github.com/pomerium/pomerium/pkg/cryptutil"
	dtestutil "github.com/pomerium/pomerium/pkg/databrokerutil/testutil"
	pom_grpc "github.com/pomerium/pomerium/pkg/grpc"
	"github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/grpc/databroker/mock_databroker"
	"github.com/pomerium/pomerium/pkg/grpc/idpsession"
	"github.com/pomerium/pomerium/pkg/grpc/session"
	"github.com/pomerium/pomerium/pkg/grpc/user"
	"github.com/pomerium/pomerium/pkg/identity"
	"github.com/pomerium/pomerium/pkg/protoutil"
	"github.com/pomerium/pomerium/pkg/ssh/code"
	"github.com/pomerium/pomerium/pkg/storage"
)

func TestStatefulSignIn(t *testing.T) {
	opts := config.NewDefaultOptions()
	tests := []struct {
		name string

		host           string
		qp             map[string]string
		validSignature bool

		sessionHandle *session.Handle
		encoder       encoding.MarshalUnmarshaler
		saveError     error

		wantErrorMsg        string
		wantRedirectBaseURL string
	}{
		{"good", "corp.example.example", map[string]string{urlutil.QueryRedirectURI: "https://dst.some.example/"}, true, &session.Handle{}, &mock.Encoder{}, nil, "", "https://dst.some.example/.pomerium/callback/"},
		{"good alternate port", "corp.example.example:8443", map[string]string{urlutil.QueryRedirectURI: "https://dst.some.example/"}, true, &session.Handle{}, &mock.Encoder{}, nil, "", "https://dst.some.example/.pomerium/callback/"},
		{"invalid signature", "corp.example.example", map[string]string{urlutil.QueryRedirectURI: "https://dst.some.example/"}, false, &session.Handle{}, &mock.Encoder{}, nil, "Bad Request:", ""},
		{"bad redirect uri query", "corp.example.example", map[string]string{urlutil.QueryRedirectURI: "^^^"}, true, &session.Handle{}, &mock.Encoder{}, nil, "Bad Request:", ""},
		{"bad marshal", "corp.example.example", map[string]string{urlutil.QueryRedirectURI: "https://dst.some.example/"}, true, &session.Handle{}, &mock.Encoder{MarshalError: errors.New("error")}, nil, "Bad Request: error", ""},
		{"good with different programmatic redirect", "corp.example.example", map[string]string{urlutil.QueryRedirectURI: "https://dst.some.example/", urlutil.QueryCallbackURI: "https://some.example"}, true, &session.Handle{}, &mock.Encoder{}, nil, "", "https://some.example"},
		{"encrypted encoder error", "corp.example.example", map[string]string{urlutil.QueryRedirectURI: "https://dst.some.example/", urlutil.QueryCallbackURI: "https://some.example"}, true, &session.Handle{}, &mock.Encoder{MarshalError: errors.New("error")}, nil, "Bad Request: error", ""},
		{"good with callback uri set", "corp.example.example", map[string]string{urlutil.QueryCallbackURI: "https://some.example/", urlutil.QueryRedirectURI: "https://dst.some.example/"}, true, &session.Handle{}, &mock.Encoder{}, nil, "", "https://some.example/"},
		{"bad callback uri set", "corp.example.example", map[string]string{urlutil.QueryCallbackURI: "^", urlutil.QueryRedirectURI: "https://dst.some.example/"}, true, &session.Handle{}, &mock.Encoder{}, nil, "Bad Request:", ""},
		{"good programmatic request", "corp.example.example", map[string]string{urlutil.QueryIsProgrammatic: "true", urlutil.QueryRedirectURI: "https://dst.some.example/"}, true, &session.Handle{}, &mock.Encoder{}, nil, "", "https://dst.some.example/.pomerium/callback/"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sessionStore := &mstore.Store{SaveError: tt.saveError}
			flow, err := NewStateful(t.Context(), trace.NewNoopTracerProvider(), config.New(opts), sessionStore, &pom_grpc.CachedOutboundGRPClientConn{})
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
			err = flow.SignIn(w, r, tt.sessionHandle)
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
	flow, err := NewStateful(t.Context(), trace.NewNoopTracerProvider(), config.New(opts), nil, &pom_grpc.CachedOutboundGRPClientConn{})
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
		sessionStore   sessions.HandleWriter

		wantErrorMsg string
	}{
		{
			"good",
			map[string]string{urlutil.QueryCallbackURI: "ok", urlutil.QuerySessionEncrypted: goodEncryptionString},
			true,
			&mock.Encoder{MarshalResponse: []byte("x")},
			&mstore.Store{SessionHandle: &session.Handle{}},
			"",
		},
		{
			"good programmatic",
			map[string]string{urlutil.QueryIsProgrammatic: "true", urlutil.QueryCallbackURI: "ok", urlutil.QuerySessionEncrypted: goodEncryptionString},
			true,
			&mock.Encoder{MarshalResponse: []byte("x")},
			&mstore.Store{SessionHandle: &session.Handle{}},
			"",
		},
		{
			"invalid signature",
			map[string]string{urlutil.QueryCallbackURI: "ok", urlutil.QuerySessionEncrypted: goodEncryptionString},
			false,
			&mock.Encoder{MarshalResponse: []byte("x")},
			&mstore.Store{SessionHandle: &session.Handle{}},
			"Bad Request:",
		},
		{
			"bad decrypt",
			map[string]string{urlutil.QuerySessionEncrypted: "KBEjQ9rnCxaAX-GOqexGw9ivEQURqts3zZ2mNGy0wnVa3SbtM399KlBq2nZ-9wM21FfsZX52er4jlmC7kPEKM3P7uZ41zR0zeys1-_74a5tQp-vsf1WXZfRsgVOuBcWPkMiWEoc379JFHxGDudp5VhU8B-dcQt4f3_PtLTHARkuH54io1Va2gNMq4Hiy8sQ1MPGCQeltH_JMzzdDpXdmdusWrXUvCGkba24muvAV06D8XRVJj6Iu9eK94qFnqcHc7wzziEbb8ADBues9dwbtb6jl8vMWz5rN6XvXqA5YpZv_MQZlsrO4oXFFQDevdgB84cX1tVbVu6qZvK_yQBZqzpOjWA9uIaoSENMytoXuWAlFO_sXjswfX8JTNdGwzB7qQRNPqxVG_sM_tzY3QhPm8zqwEzsXG5DokxZfVt2I5WJRUEovFDb4BnK9KFnnkEzLEdMudixVnXeGmTtycgJvoTeTCQRPfDYkcgJ7oKf4tGea-W7z5UAVa2RduJM9ZoM6YtJX7jgDm__PvvqcE0knJUF87XHBzdcOjoDF-CUze9xDJgNBlvPbJqVshKrwoqSYpePSDH9GUCNKxGequW3Ma8GvlFfhwd0rK6IZG-XWkyk0XSWQIGkDSjAvhB1wsOusCCguDjbpVZpaW5MMyTkmx68pl6qlIKT5UCcrVPl4ix5ZEj91mUDF0O1t04haD7VZuLVFXVGmqtFrBKI76sdYN-zkokaa1_chPRTyqMQFlqu_8LD6-RiK3UccGM-dEmnX72i91NP9F9OK0WJr9Cheup1C_P0mjqAO4Cb8oIHm0Oxz_mRqv5QbTGJtb3xwPLPuVjVCiE4gGBcuU2ixpSVf5HUF7y1KicVMCKiX9ATCBtg8sTdQZQnPEtHcHHAvdsnDVwev1LGfqA-Gdvg="},
			true,
			&mock.Encoder{MarshalResponse: []byte("x")},
			&mstore.Store{SessionHandle: &session.Handle{}},
			"proxy: callback token decrypt error:",
		},
		{
			"bad save session",
			map[string]string{urlutil.QuerySessionEncrypted: goodEncryptionString},
			true,
			&mock.Encoder{MarshalResponse: []byte("x")},
			&mstore.Store{SaveError: errors.New("hi")},
			"Internal Server Error: proxy: error saving session handle:",
		},
		{
			"bad base64",
			map[string]string{urlutil.QuerySessionEncrypted: "^"},
			true,
			&mock.Encoder{MarshalResponse: []byte("x")},
			&mstore.Store{SessionHandle: &session.Handle{}},
			"proxy: malfromed callback token:",
		},
		{
			"malformed redirect",
			nil,
			true,
			&mock.Encoder{},
			&mstore.Store{SessionHandle: &session.Handle{}},
			"Bad Request:",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			flow, err := NewStateful(t.Context(), trace.NewNoopTracerProvider(), config.New(opts), tt.sessionStore, &pom_grpc.CachedOutboundGRPClientConn{})
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
		config.New(opts),
		&mstore.Store{SessionHandle: &session.Handle{}},
		&pom_grpc.CachedOutboundGRPClientConn{},
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
	for _, tc := range []struct {
		name      string
		sid       *string
		wantHints SignOutHints
	}{
		{
			name:      "no SID",
			wantHints: SignOutHints{IDTokenHint: "current"},
		},
		{
			name:      "has SID",
			sid:       new("sid"),
			wantHints: SignOutHints{LogoutHint: "sid", IDTokenHint: "new"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sessions := []*idpsession.IDPSession{
				{
					Id: "one", Sid: tc.sid,
					IdToken:    &idpsession.IDToken{Raw: "current", IssuedAt: timestamppb.New(time.Unix(1, 0))},
					OauthToken: &idpsession.OAuthToken{AccessToken: "access", RefreshToken: "refresh"},
				},
				{
					Id: "two", Sid: tc.sid,
					IdToken:    &idpsession.IDToken{Raw: "new", IssuedAt: timestamppb.New(time.Unix(2, 0))},
					OauthToken: &idpsession.OAuthToken{AccessToken: "access-2", RefreshToken: "refresh-2"},
				},
			}
			bindingMgr := &mockBindingManager{
				revocation: IDPSessionRevocation{Source: sessions[0], Sessions: sessions},
			}
			authenticator := &mockAuthenticator{}
			client := mock_databroker.NewMockDataBrokerServiceClient(gomock.NewController(t))
			flow := &Stateful{dataBrokerClient: client, bindingMgr: bindingMgr}
			h := &session.Handle{Id: "session-id", UserId: "user-id"}

			// check the flow still revokes the session associated with the handle.
			client.EXPECT().Get(t.Context(), matchers.ProtoEq(&databroker.GetRequest{
				Type: "type.googleapis.com/session.Session",
				Id:   h.Id,
			})).Return(&databroker.GetResponse{Record: databroker.NewRecord(&session.Session{
				Id: h.Id, UserId: h.UserId,
			})}, nil)
			client.EXPECT().Put(t.Context(), gomock.Any()).DoAndReturn(
				func(_ context.Context, req *databroker.PutRequest, _ ...grpc.CallOption) (*databroker.PutResponse, error) {
					require.Len(t, req.GetRecords(), 1)
					record := req.GetRecord()
					assert.Equal(t, "type.googleapis.com/session.Session", record.GetType())
					assert.Equal(t, h.Id, record.GetId())
					assert.NotNil(t, record.GetDeletedAt())
					var deletedSession session.Session
					require.NoError(t, record.GetData().UnmarshalTo(&deletedSession))
					assert.Equal(t, h.UserId, deletedSession.GetUserId())
					return &databroker.PutResponse{}, nil
				},
			)

			hints := flow.RevokeSession(t.Context(), nil, authenticator, h)

			assert.Equal(t, tc.wantHints, hints)
			assert.Same(t, h, bindingMgr.handle)
			assert.ElementsMatch(t, []*oauth2.Token{
				idpsession.FromOAuthToken(sessions[0]),
				idpsession.FromOAuthToken(sessions[1]),
			}, authenticator.revokedTokens)
		})
	}
}

func TestPersistSession(t *testing.T) {
	timeNow = func() time.Time { return time.Unix(1721965100, 0) }
	t.Cleanup(func() { timeNow = time.Now })

	opts := config.NewDefaultOptions()
	opts.CookieExpire = 4 * time.Hour
	flow, err := NewStateful(t.Context(), noop.NewTracerProvider(), config.New(opts), nil, &pom_grpc.CachedOutboundGRPClientConn{})
	require.NoError(t, err)

	ctrl := gomock.NewController(t)
	client := mock_databroker.NewMockDataBrokerServiceClient(ctrl)
	flow.dataBrokerClient = client

	ctx := t.Context()

	client.EXPECT().Get(ctx, matchers.ProtoEq(&databroker.GetRequest{
		Type: "type.googleapis.com/user.User",
		Id:   "user-id",
	})).Return(&databroker.GetResponse{}, nil)

	// PersistSession should copy data from the sessions.Handle,
	// identity.SessionClaims, and oauth2.Token into a Session and User record.
	h := &session.Handle{
		Id:                 "session-id",
		UserId:             "user-id",
		IdentityProviderId: "idp-id",
		Aud:                jwt.Audience{"route.example.com"},
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
			require.Len(t, r.Records, 4)
			byTypeAndID := make(map[string]*databroker.Record)
			for _, record := range r.GetRecords() {
				byTypeAndID[record.GetType()+"/"+record.GetId()] = record
				assert.Nil(t, record.GetDeletedAt())
			}

			userRecord := byTypeAndID["type.googleapis.com/user.User/user-id"]
			require.NotNil(t, userRecord)
			var u user.User
			require.NoError(t, userRecord.GetData().UnmarshalTo(&u))
			assert.Equal(t, expectedClaims, u.Claims)

			record := byTypeAndID["type.googleapis.com/session.Session/session-id"]
			require.NotNil(t, record)
			idpSessID := idpSessionID("browser-id", "user-id")
			require.NotNil(t, byTypeAndID["type.googleapis.com/idpsession.IDPSession/"+idpSessID])
			bindingRecord := byTypeAndID["type.googleapis.com/idpsession.Binding/session-id"]
			require.NotNil(t, bindingRecord)
			var binding idpsession.Binding
			require.NoError(t, bindingRecord.GetData().UnmarshalTo(&binding))
			assert.Equal(t, idpSessID, binding.GetIdpSessionId())
			assert.Equal(t, "user-id", binding.GetUserId())

			var s session.Session
			record.GetData().UnmarshalTo(&s)
			testutil.AssertProtoEqual(t, &session.Session{
				Id:         "session-id",
				UserId:     "user-id",
				IdpId:      "idp-id",
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

	req := httptest.NewRequest(http.MethodGet, "https://authenticate.example.com/callback", nil)
	req.Header.Set("User-Agent", "test-browser/1.0")
	err = flow.PersistSession(ctx, nil, req, h, claims, accessToken, "browser-id", "sid")
	assert.NoError(t, err)
	assert.Equal(t, proto.Uint64(1111), h.DatabrokerRecordVersion)
	assert.Equal(t, proto.Uint64(2222), h.DatabrokerServerVersion)
}

func TestStatefulAuthenticatePendingSession(t *testing.T) {
	t.Parallel()

	opts := config.NewDefaultOptions()
	client := dtestutil.NewTestDatabroker(t)
	flow, err := NewStateful(
		t.Context(), noop.NewTracerProvider(), config.New(opts), nil, &pom_grpc.CachedOutboundGRPClientConn{})
	require.NoError(t, err)
	flow.dataBrokerClient = client
	flow.codeReader = code.NewReader(databroker.NewStaticClientGetter(client))

	t.Run("code denied", func(t *testing.T) {
		t.Parallel()
		code := [16]byte{}
		_, _ = rand.Read(code[:])
		codeStr := base64.RawURLEncoding.EncodeToString(code[:])

		setupRecords := newPendingSessionRecords(
			pendingAuthInfo{
				idpSessionID: "is1",
				sessionID:    "s1",
				userID:       "u1",
				idpID:        "idp1",
				code:         codeStr,
				sshKey:       "foo",
			},
		)

		_, err := client.Put(t.Context(), &databroker.PutRequest{
			Records: setupRecords,
		})

		require.NoError(t, err)

		uri := &url.URL{
			Host: "https://authenticate.example.com",
			Path: "/.pomerium/sign",
		}
		// the lack of confirm=true means the user submitted deny for the code from the UI
		v := uri.Query()
		v.Add("user_code", codeStr)
		uri.RawQuery = v.Encode()

		r := httptest.NewRequest(http.MethodPost, uri.String(), nil)

		w := httptest.NewRecorder()
		h := &session.Handle{
			Id:                 "s1",
			UserId:             "u1",
			IdentityProviderId: "idp1",
		}
		err = flow.AuthenticatePendingSession(w, r, h)
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, w.Result().StatusCode, "unexpected http status code from user code denial")

		sbr := &session.SessionBindingRequest{}
		resp, err := client.Get(t.Context(), &databroker.GetRequest{
			Type: protoutil.GetTypeURL(sbr),
			Id:   codeStr,
		})
		require.NoError(t, err)
		require.NoError(t, resp.GetRecord().GetData().UnmarshalTo(sbr))
		assert.Equal(t, session.SessionBindingRequestState_Revoked, sbr.State)

		// assert the projected session / idpsession binding were not created
		_, err = client.Get(t.Context(), &databroker.GetRequest{
			Type: protoutil.GetTypeURL(new(session.Session)),
			Id:   "foo", // matches the ssh key
		})
		assert.Error(t, err)
		assert.Equal(t, codes.NotFound, status.Code(err))

		_, err = client.Get(t.Context(), &databroker.GetRequest{
			Type: protoutil.GetTypeURL(new(idpsession.Binding)),
			Id:   "foo", // matches the ssh key
		})
		assert.Error(t, err)
		assert.Equal(t, codes.NotFound, status.Code(err))

		// replaying a code where a decision has been made returns an error
		w2 := httptest.NewRecorder()
		r2 := httptest.NewRequest(http.MethodPost, uri.String(), nil)
		err = flow.AuthenticatePendingSession(w2, r2, h)
		assert.Error(t, err)
		var httpErr *httputil.HTTPError
		require.True(t, errors.As(err, &httpErr))
		assert.Equal(t, http.StatusConflict, httpErr.Status)
	})

	t.Run("code success", func(t *testing.T) {
		t.Parallel()
		code := [16]byte{}
		_, _ = rand.Read(code[:])
		codeStr := base64.RawURLEncoding.EncodeToString(code[:])

		setupRecords := newPendingSessionRecords(
			pendingAuthInfo{
				idpSessionID: "is2",
				sessionID:    "s2",
				userID:       "u2",
				idpID:        "idp1",
				code:         codeStr,
				sshKey:       "bar",
			},
		)

		_, err := client.Put(t.Context(), &databroker.PutRequest{
			Records: setupRecords,
		})

		require.NoError(t, err)

		uri := &url.URL{
			Host: "https://authenticate.example.com",
			Path: "/.pomerium/sign",
		}
		v := uri.Query()
		v.Add("user_code", codeStr)
		v.Add("confirm", "true")
		uri.RawQuery = v.Encode()

		r := httptest.NewRequest(http.MethodPost, uri.String(), nil)
		w := httptest.NewRecorder()
		h := &session.Handle{
			Id:                 "s2",
			UserId:             "u2",
			IdentityProviderId: "idp1",
		}
		err = flow.AuthenticatePendingSession(w, r, h)
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, w.Result().StatusCode, "unexpected http status code from user code approval")

		sbr := &session.SessionBindingRequest{}
		resp, err := client.Get(t.Context(), &databroker.GetRequest{
			Type: protoutil.GetTypeURL(sbr),
			Id:   codeStr,
		})
		require.NoError(t, err)
		require.NoError(t, resp.GetRecord().GetData().UnmarshalTo(sbr))
		assert.Equal(t, session.SessionBindingRequestState_Accepted, sbr.State)

		// assert the new project session and idpsession binding are created.

		_, err = client.Get(t.Context(), &databroker.GetRequest{
			Type: protoutil.GetTypeURL(new(session.Session)),
			Id:   "bar", // matches ssh key
		})
		assert.NoError(t, err, "expected new session to be created")

		_, err = client.Get(t.Context(), &databroker.GetRequest{
			Type: protoutil.GetTypeURL(new(idpsession.Binding)),
			Id:   "bar", // matches ssh key
		})
		assert.NoError(t, err, "expected new idp session binding to be created")

		// replaying a code where a decision has been made returns an error
		w2 := httptest.NewRecorder()
		r2 := httptest.NewRequest(http.MethodPost, uri.String(), nil)
		err = flow.AuthenticatePendingSession(w2, r2, h)
		assert.Error(t, err)
		var httpErr *httputil.HTTPError
		assert.True(t, errors.As(err, &httpErr))
		assert.Equal(t, http.StatusConflict, httpErr.Status)
	})

	t.Run("do not prompt again", func(t *testing.T) {
		t.Parallel()
		code := [16]byte{}
		_, _ = rand.Read(code[:])
		codeStr := base64.RawURLEncoding.EncodeToString(code[:])

		setupRecords := newPendingSessionRecords(
			pendingAuthInfo{
				idpSessionID: "is3",
				sessionID:    "s3",
				userID:       "u3",
				idpID:        "idp1",
				code:         codeStr,
				sshKey:       "baz",
			},
		)

		_, err := client.Put(t.Context(), &databroker.PutRequest{
			Records: setupRecords,
		})

		require.NoError(t, err)

		uri := &url.URL{
			Host: "https://authenticate.example.com",
			Path: "/.pomerium/sign",
		}
		v := uri.Query()
		v.Add("user_code", codeStr)
		v.Add("confirm", "true")
		v.Add("create_id_binding", "true")
		uri.RawQuery = v.Encode()

		r := httptest.NewRequest(http.MethodPost, uri.String(), nil)
		w := httptest.NewRecorder()
		h := &session.Handle{
			Id:                 "s3",
			UserId:             "u3",
			IdentityProviderId: "idp1",
		}
		err = flow.AuthenticatePendingSession(w, r, h)
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, w.Result().StatusCode, "unexpected http status code from user code approval")

		sbr := &session.SessionBindingRequest{}
		resp, err := client.Get(t.Context(), &databroker.GetRequest{
			Type: protoutil.GetTypeURL(sbr),
			Id:   codeStr,
		})
		require.NoError(t, err)
		require.NoError(t, resp.GetRecord().GetData().UnmarshalTo(sbr))
		assert.Equal(t, session.SessionBindingRequestState_Accepted, sbr.State)

		// assert the new project session and idpsession binding are created.

		_, err = client.Get(t.Context(), &databroker.GetRequest{
			Type: protoutil.GetTypeURL(new(session.Session)),
			Id:   "baz", // matches ssh key
		})
		assert.NoError(t, err, "expected new session to be created")

		_, err = client.Get(t.Context(), &databroker.GetRequest{
			Type: protoutil.GetTypeURL(new(idpsession.Binding)),
			Id:   "baz", // matches ssh key
		})
		assert.NoError(t, err, "expected new idp session binding to be created")

		// delete the ssh session (simulating a revocation/expiration)
		_, err = storage.DeleteDataBrokerRecord(t.Context(), client, protoutil.GetTypeURL(new(session.Session)), "baz")
		require.NoError(t, err)
		_, err = storage.DeleteDataBrokerRecord(t.Context(), client, protoutil.GetTypeURL(new(idpsession.Binding)), "baz")
		require.NoError(t, err)

		// issue new code

		newCode := [16]byte{}
		_, _ = rand.Read(code[:])
		newCodeStr := base64.RawURLEncoding.EncodeToString(newCode[:])

		newSbr := &session.SessionBindingRequest{
			Protocol:  "ssh",
			Key:       "baz",
			IdpId:     "idp1",
			CreatedAt: timestamppb.Now(),
			ExpiresAt: timestamppb.New(time.Now().Add(time.Hour)),
			State:     session.SessionBindingRequestState_InFlight,
		}

		_, err = client.Put(t.Context(), &databroker.PutRequest{
			Records: []*databroker.Record{
				{
					Type: protoutil.GetTypeURL(newSbr),
					Id:   newCodeStr,
					Data: protoutil.NewAny(newSbr),
				},
			},
		})
		require.NoError(t, err)
		signInVerifyURI := &url.URL{
			Host: "https://authenticate.example.com",
			Path: "/.pomerium/sign",
		}
		v2 := signInVerifyURI.Query()
		v2.Add("user_code", newCodeStr)
		signInVerifyURI.RawQuery = v2.Encode()

		w2 := httptest.NewRecorder()
		// GET normally displays the confirmation prompt without the identity binding
		// but when the identity binding exists, we expect it to recreate a valid ssh session.
		r2 := httptest.NewRequest(http.MethodGet, signInVerifyURI.String(), nil)
		require.NoError(t, flow.AuthenticatePendingSession(w2, r2, h))

		assert.Equal(t, http.StatusOK, w2.Result().StatusCode)
		_, err = client.Get(t.Context(), &databroker.GetRequest{
			Type: protoutil.GetTypeURL(new(session.Session)),
			Id:   "baz",
		})
		assert.NoError(t, err, "expect session to be recreated without confirmation prompt")

		_, err = client.Get(t.Context(), &databroker.GetRequest{
			Type: protoutil.GetTypeURL(new(idpsession.Binding)),
			Id:   "baz",
		})
		assert.NoError(t, err, "expect binding to be recreated without confirmation prompt")
	})
}

type pendingAuthInfo struct {
	idpSessionID string
	sessionID    string
	userID       string
	idpID        string
	code         string
	sshKey       string
}

func newPendingSessionRecords(info pendingAuthInfo) []*databroker.Record {
	setupRecords := []*databroker.Record{}
	idpSess := &idpsession.IDPSession{
		Id:     info.idpSessionID,
		UserId: info.userID,
		IdpId:  info.idpID,
	}
	sess := &session.Session{
		Id: info.sessionID,
	}
	codeRequest := &session.SessionBindingRequest{
		Protocol:  "ssh",
		Key:       info.sshKey,
		IdpId:     info.idpID,
		CreatedAt: timestamppb.Now(),
		ExpiresAt: timestamppb.New(time.Now().Add(time.Hour)),
		State:     session.SessionBindingRequestState_InFlight,
	}
	setupRecords = append(setupRecords, &databroker.Record{
		Type: protoutil.GetTypeURL(codeRequest),
		Id:   info.code,
		Data: protoutil.NewAny(codeRequest),
	})
	setupRecords = append(setupRecords, databroker.NewRecord(idpSess))
	setupRecords = append(setupRecords, idpsession.NewBoundRecords(
		idpSess.Id,
		info.userID,
		idpsession.BindingProtocol_BINDING_PROTOCOL_BROWSER,
		map[string]string{},
		sess,
	)...)

	return setupRecords
}

type mockAuthenticator struct {
	identity.Authenticator

	revokedTokens []*oauth2.Token
	revokeError   error
}

type mockBindingManager struct {
	BindingManager
	revocation IDPSessionRevocation
	handle     *session.Handle
}

func (m *mockBindingManager) DeleteUpstreamIDPSessions(_ context.Context, h *session.Handle) (IDPSessionRevocation, error) {
	m.handle = h
	return m.revocation, nil
}

func (a *mockAuthenticator) Revoke(_ context.Context, token *oauth2.Token) error {
	a.revokedTokens = append(a.revokedTokens, token)
	return a.revokeError
}
