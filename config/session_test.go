package config

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/pires/go-proxyproto"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/trace/noop"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/testing/protocmp"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/pomerium/pomerium/internal/encoding/jws"
	"github.com/pomerium/pomerium/internal/httputil"
	"github.com/pomerium/pomerium/internal/jwtutil"
	"github.com/pomerium/pomerium/internal/sessions"
	"github.com/pomerium/pomerium/internal/testutil"
	"github.com/pomerium/pomerium/internal/testutil/mockidp"
	"github.com/pomerium/pomerium/internal/urlutil"
	"github.com/pomerium/pomerium/pkg/authenticateapi"
	"github.com/pomerium/pomerium/pkg/cryptutil"
	"github.com/pomerium/pomerium/pkg/grpc/config"
	"github.com/pomerium/pomerium/pkg/grpc/databroker"
	identitypb "github.com/pomerium/pomerium/pkg/grpc/identity"
	"github.com/pomerium/pomerium/pkg/grpc/session"
	"github.com/pomerium/pomerium/pkg/grpc/user"
	"github.com/pomerium/pomerium/pkg/identity"
	"github.com/pomerium/pomerium/pkg/nullable"
	"github.com/pomerium/pomerium/pkg/storage"
)

func TestSessionStore_LoadSessionState(t *testing.T) {
	t.Parallel()

	sharedKey := cryptutil.NewKey()
	options := NewDefaultOptions()
	options.SharedKey = base64.StdEncoding.EncodeToString(sharedKey)
	options.Provider = "oidc"
	options.ProviderURL = "https://oidc.example.com"
	options.ClientID = "client_id"
	options.ClientSecret = "client_secret"
	options.Policies = append(options.Policies,
		Policy{
			From:            "https://p1.example.com",
			To:              mustParseWeightedURLs(t, "https://p1"),
			IDPClientID:     "client_id_1",
			IDPClientSecret: "client_secret_1",
		},
		Policy{
			From:            "https://p2.example.com",
			To:              mustParseWeightedURLs(t, "https://p2"),
			IDPClientID:     "client_id_2",
			IDPClientSecret: "client_secret_2",
		})
	require.NoError(t, options.Validate())

	store, err := NewSessionStore(options)
	require.NoError(t, err)

	idp1, err := options.GetIdentityProviderForPolicy(nil)
	require.NoError(t, err)
	require.NotNil(t, idp1)

	idp2, err := options.GetIdentityProviderForPolicy(&options.Policies[0])
	require.NoError(t, err)
	require.NotNil(t, idp2)

	idp3, err := options.GetIdentityProviderForPolicy(&options.Policies[1])
	require.NoError(t, err)
	require.NotNil(t, idp3)

	makeJWS := func(t *testing.T, h *session.Handle) string {
		e, err := jws.NewHS256Signer(sharedKey)
		require.NoError(t, err)

		rawJWS, err := e.Marshal(h)
		require.NoError(t, err)

		return string(rawJWS)
	}

	t.Run("mssing", func(t *testing.T) {
		r, err := http.NewRequest(http.MethodGet, "https://p1.example.com", nil)
		require.NoError(t, err)
		h, err := store.ReadSessionHandleAndCheckIDP(r)
		assert.ErrorIs(t, err, sessions.ErrNoSessionFound)
		assert.Nil(t, h)
	})
	t.Run("query", func(t *testing.T) {
		rawJWS := makeJWS(t, &session.Handle{
			Iss:                new("authenticate.example.com"),
			Id:                 "example",
			IdentityProviderId: idp2.GetId(),
		})

		r, err := http.NewRequest(http.MethodGet, "https://p1.example.com?"+url.Values{
			urlutil.QuerySession: {rawJWS},
		}.Encode(), nil)
		require.NoError(t, err)
		h, err := store.ReadSessionHandleAndCheckIDP(r)
		assert.NoError(t, err)
		assert.Empty(t, cmp.Diff(&session.Handle{
			Iss:                new("authenticate.example.com"),
			Id:                 "example",
			IdentityProviderId: idp2.GetId(),
		}, h, protocmp.Transform()))
	})
	t.Run("header", func(t *testing.T) {
		rawJWS := makeJWS(t, &session.Handle{
			Iss:                new("authenticate.example.com"),
			Id:                 "example",
			IdentityProviderId: idp3.GetId(),
		})

		r, err := http.NewRequest(http.MethodGet, "https://p2.example.com", nil)
		require.NoError(t, err)
		r.Header.Set(httputil.HeaderPomeriumAuthorization, rawJWS)
		h, err := store.ReadSessionHandleAndCheckIDP(r)
		assert.NoError(t, err)
		assert.Empty(t, cmp.Diff(&session.Handle{
			Iss:                new("authenticate.example.com"),
			Id:                 "example",
			IdentityProviderId: idp3.GetId(),
		}, h, protocmp.Transform()))
	})
	t.Run("wrong idp", func(t *testing.T) {
		rawJWS := makeJWS(t, &session.Handle{
			Iss:                new("authenticate.example.com"),
			Id:                 "example",
			IdentityProviderId: idp1.GetId(),
		})

		r, err := http.NewRequest(http.MethodGet, "https://p2.example.com", nil)
		require.NoError(t, err)
		r.Header.Set(httputil.HeaderPomeriumAuthorization, rawJWS)
		h, err := store.ReadSessionHandleAndCheckIDP(r)
		assert.Error(t, err)
		assert.Nil(t, h)
	})
	t.Run("blank idp", func(t *testing.T) {
		rawJWS := makeJWS(t, &session.Handle{
			Iss: new("authenticate.example.com"),
			Id:  "example",
		})

		r, err := http.NewRequest(http.MethodGet, "https://p2.example.com", nil)
		require.NoError(t, err)
		r.Header.Set(httputil.HeaderPomeriumAuthorization, rawJWS)
		h, err := store.ReadSessionHandleAndCheckIDP(r)
		assert.NoError(t, err)
		assert.Empty(t, cmp.Diff(&session.Handle{
			Iss: new("authenticate.example.com"),
			Id:  "example",
		}, h, protocmp.Transform()))
	})
}

func TestGetIdentityProviderDetectsChangesToAuthenticateServiceURL(t *testing.T) {
	t.Parallel()

	options := NewDefaultOptions()
	options.AuthenticateURLString = "https://authenticate.example.com"
	options.Provider = "oidc"
	options.ProviderURL = "https://oidc.example.com"
	options.ClientID = "client_id"
	options.ClientSecret = "client_secret"

	idp1, err := options.GetIdentityProviderForPolicy(nil)
	require.NoError(t, err)

	options.AuthenticateURLString = ""

	idp2, err := options.GetIdentityProviderForPolicy(nil)
	require.NoError(t, err)

	assert.NotEqual(t, idp1.GetId(), idp2.GetId(),
		"identity provider should change when authenticate service url changes")
}

func Test_getTokenSessionID(t *testing.T) {
	t.Parallel()

	assert.Equal(t, "532b0a3d-b413-50a0-8c9f-e6eb340a05d3", getAccessTokenSessionID(nil, "TOKEN"))
	assert.Equal(t, "e0b8096c-54dd-5623-8098-5488f9c302db", getIdentityTokenSessionID(nil, "TOKEN"))
	assert.Equal(t, "9c99d1d0-805e-51cb-b808-772ab654268b", getAccessTokenSessionID(&identitypb.Provider{Id: "IDP1"}, "TOKEN"))
	assert.Equal(t, "0fe0e289-40bb-5ffe-b328-e290e043a652", getIdentityTokenSessionID(&identitypb.Provider{Id: "IDP1"}, "TOKEN"))
	assert.Equal(t, "9175ce67-7b36-5d30-a901-26314c546a5a", jwtProviderSessionID("k8s-prod", "TOKEN"))
}

func TestGetIncomingBearerToken(t *testing.T) {
	t.Parallel()

	fmtDefault := config.BearerTokenFormat_BEARER_TOKEN_FORMAT_DEFAULT
	fmtAccess := config.BearerTokenFormat_BEARER_TOKEN_FORMAT_IDP_ACCESS_TOKEN
	fmtIdentity := config.BearerTokenFormat_BEARER_TOKEN_FORMAT_IDP_IDENTITY_TOKEN
	fmtJWT := config.BearerTokenFormat_BEARER_TOKEN_FORMAT_JWT

	for _, tc := range []struct {
		name           string
		globalFormat   *config.BearerTokenFormat
		routeFormat    *config.BearerTokenFormat
		headers        http.Header
		expectedOK     bool
		expectedToken  string
		expectedFormat config.BearerTokenFormat
	}{
		{
			name:       "empty headers, passthrough",
			expectedOK: false,
		},
		{
			name:       "unset format ignores bearer (passthrough)",
			headers:    http.Header{"Authorization": {"Bearer tok"}},
			expectedOK: false,
		},
		{
			name:           "default format ignores bearer",
			globalFormat:   &fmtDefault,
			headers:        http.Header{"Authorization": {"Bearer tok"}},
			expectedOK:     false,
			expectedFormat: fmtDefault,
		},
		{
			name:           "access token via options",
			globalFormat:   &fmtAccess,
			headers:        http.Header{"Authorization": {"Bearer tok"}},
			expectedOK:     true,
			expectedToken:  "tok",
			expectedFormat: fmtAccess,
		},
		{
			name:           "access token via route override",
			routeFormat:    &fmtAccess,
			headers:        http.Header{"Authorization": {"Bearer tok"}},
			expectedOK:     true,
			expectedToken:  "tok",
			expectedFormat: fmtAccess,
		},
		{
			name:           "identity token",
			globalFormat:   &fmtIdentity,
			headers:        http.Header{"Authorization": {"Bearer id-tok"}},
			expectedOK:     true,
			expectedToken:  "id-tok",
			expectedFormat: fmtIdentity,
		},
		{
			name:           "jwt",
			routeFormat:    &fmtJWT,
			headers:        http.Header{"Authorization": {"Bearer jwt-tok"}},
			expectedOK:     true,
			expectedToken:  "jwt-tok",
			expectedFormat: fmtJWT,
		},
		{
			name:           "jwt but non-Bearer auth header",
			routeFormat:    &fmtJWT,
			headers:        http.Header{"Authorization": {"Basic dXNlcjpwYXNz"}},
			expectedOK:     false,
			expectedFormat: fmtJWT,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			cfg := New(NewDefaultOptions())
			cfg.Options.BearerTokenFormat = nullable.FromPtr(tc.globalFormat)

			var route *Policy
			if tc.routeFormat != nil {
				route = &Policy{
					RouteOptions: RouteOptions{
						BearerTokenFormat: nullable.FromPtr(tc.routeFormat),
					},
				}
			}

			r, err := http.NewRequest(http.MethodGet, "https://example.com", nil)
			require.NoError(t, err)
			if tc.headers != nil {
				r.Header = tc.headers
			}

			actualToken, actualFormat, actualOK := cfg.getIncomingBearerToken(route, r)
			assert.Equal(t, tc.expectedOK, actualOK)
			assert.Equal(t, tc.expectedToken, actualToken)
			assert.Equal(t, tc.expectedFormat, actualFormat)
		})
	}
}

func Test_newSessionFromIDPClaims(t *testing.T) {
	t.Parallel()

	tm1 := time.Date(2025, 2, 18, 8, 6, 0, 0, time.UTC)
	tm2 := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	tm3 := tm2.Add(time.Hour)

	for _, tc := range []struct {
		name      string
		sessionID string
		claims    jwtutil.Claims
		expect    *session.Session
	}{
		{
			"empty claims", "S1",
			nil,
			&session.Session{
				Id:              "S1",
				AccessedAt:      timestamppb.New(tm1),
				ExpiresAt:       timestamppb.New(tm1.Add(time.Hour * 14)),
				IssuedAt:        timestamppb.New(tm1),
				RefreshDisabled: true,
			},
		},
		{
			"full claims", "S2",
			jwtutil.Claims{
				"aud": "https://www.example.com",
				"sub": "U1",
				"iat": tm2.Unix(),
				"exp": tm3.Unix(),
			},
			&session.Session{
				Id:         "S2",
				UserId:     "U1",
				AccessedAt: timestamppb.New(tm1),
				ExpiresAt:  timestamppb.New(tm3),
				IssuedAt:   timestamppb.New(tm2),
				Audience:   []string{"https://www.example.com"},
				Claims: identity.FlattenedClaims{
					"aud": {"https://www.example.com"},
					"sub": {"U1"},
					"iat": {tm2.Unix()},
					"exp": {tm3.Unix()},
				}.ToPB(),
				RefreshDisabled: true,
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			cfg := New(NewDefaultOptions())
			c := &incomingIDPTokenSessionCreator{
				timeNow: func() time.Time { return tm1 },
			}
			actual := c.newSessionFromIDPClaims(cfg, "", tc.sessionID, tc.claims)
			testutil.AssertProtoEqual(t, tc.expect, actual)
		})
	}
}

func Test_fillUserFromIDPClaims(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name    string
		claims  jwtutil.Claims
		current *user.User
		expect  *user.User
	}{
		{"empty claims", nil, nil, &user.User{}},
		{"full claims", jwtutil.Claims{
			"sub":   "USER_ID",
			"name":  "NAME",
			"email": "EMAIL",
		}, nil, &user.User{
			Id:    "USER_ID",
			Name:  "NAME",
			Email: "EMAIL",
			Claims: identity.FlattenedClaims{
				"sub":   {"USER_ID"},
				"name":  {"NAME"},
				"email": {"EMAIL"},
			}.ToPB(),
		}},
		{"existing claims", jwtutil.Claims{
			"sub": "USER_ID",
		}, &user.User{
			Id:    "USER_ID",
			Name:  "NAME",
			Email: "EMAIL",
			Claims: identity.FlattenedClaims{
				"sub":   {"USER_ID"},
				"name":  {"NAME"},
				"email": {"EMAIL"},
			}.ToPB(),
		}, &user.User{
			Id:    "USER_ID",
			Name:  "NAME",
			Email: "EMAIL",
			Claims: identity.FlattenedClaims{
				"sub":   {"USER_ID"},
				"name":  {"NAME"},
				"email": {"EMAIL"},
			}.ToPB(),
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			actual := new(user.User)
			if tc.current != nil {
				actual = proto.Clone(tc.current).(*user.User)
			}
			new(incomingIDPTokenSessionCreator).fillUserFromIDPClaims(actual, tc.claims)
			testutil.AssertProtoEqual(t, tc.expect, actual)
		})
	}
}

func TestIncomingIDPTokenSessionCreator_CreateSession(t *testing.T) {
	t.Parallel()

	t.Run("access_token", func(t *testing.T) {
		t.Parallel()

		mux := http.NewServeMux()
		mux.HandleFunc("/.pomerium/verify-access-token", func(w http.ResponseWriter, _ *http.Request) {
			json.NewEncoder(w).Encode(&authenticateapi.VerifyTokenResponse{
				Valid:  true,
				Claims: jwtutil.Claims{"sub": "U1"},
			})
		})
		srv := httptest.NewTLSServer(mux)

		ctx := testutil.GetContext(t, time.Minute)
		cfg := New(NewDefaultOptions())
		cfg.Options.AuthenticateURLString = srv.URL
		cfg.Options.ClientSecret = "CLIENT_SECRET_1"
		cfg.Options.ClientID = "CLIENT_ID_1"
		cfg.Options.BearerTokenFormat = nullable.From(config.BearerTokenFormat_BEARER_TOKEN_FORMAT_IDP_ACCESS_TOKEN)
		route := &Policy{}
		route.IDPClientSecret = "CLIENT_SECRET_2"
		route.IDPClientID = "CLIENT_ID_2"
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://www.example.com", nil)
		require.NoError(t, err)
		req.Header.Set("Authorization", "Bearer ACCESS_TOKEN")
		c := NewIncomingIDPTokenSessionCreator(
			noop.NewTracerProvider(),
			func(_ context.Context, _, _ string) (*databroker.Record, error) {
				return nil, storage.ErrNotFound
			},
			func(_ context.Context, records []*databroker.Record) error {
				if assert.Len(t, records, 2, "should put session and user") {
					assert.Equal(t, "type.googleapis.com/session.Session", records[0].Type)
					assert.Equal(t, "type.googleapis.com/user.User", records[1].Type)
				}
				return nil
			},
		)
		s, err := c.CreateSession(ctx, cfg, route, req)
		assert.NoError(t, err)
		assert.Equal(t, "U1", s.GetUserId())
		assert.Equal(t, "ACCESS_TOKEN", s.GetOauthToken().GetAccessToken())
		assert.True(t, s.GetRefreshDisabled())
	})
	t.Run("identity_token", func(t *testing.T) {
		t.Parallel()

		mux := http.NewServeMux()
		mux.HandleFunc("/.pomerium/verify-identity-token", func(w http.ResponseWriter, _ *http.Request) {
			json.NewEncoder(w).Encode(&authenticateapi.VerifyTokenResponse{
				Valid:  true,
				Claims: jwtutil.Claims{"sub": "U1"},
			})
		})
		srv := httptest.NewTLSServer(mux)

		ctx := testutil.GetContext(t, time.Minute)
		cfg := New(NewDefaultOptions())
		cfg.Options.AuthenticateURLString = srv.URL
		cfg.Options.ClientSecret = "CLIENT_SECRET_1"
		cfg.Options.ClientID = "CLIENT_ID_1"
		cfg.Options.BearerTokenFormat = nullable.From(*config.BearerTokenFormat_BEARER_TOKEN_FORMAT_IDP_IDENTITY_TOKEN.Enum())
		route := &Policy{}
		route.IDPClientSecret = "CLIENT_SECRET_2"
		route.IDPClientID = "CLIENT_ID_2"
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://www.example.com", nil)
		require.NoError(t, err)
		req.Header.Set("Authorization", "Bearer IDENTITY_TOKEN")
		c := NewIncomingIDPTokenSessionCreator(
			noop.NewTracerProvider(),
			func(_ context.Context, _, _ string) (*databroker.Record, error) {
				return nil, storage.ErrNotFound
			},
			func(_ context.Context, records []*databroker.Record) error {
				if assert.Len(t, records, 2, "should put session and user") {
					assert.Equal(t, "type.googleapis.com/session.Session", records[0].Type)
					assert.Equal(t, "type.googleapis.com/user.User", records[1].Type)
				}
				return nil
			},
		)
		s, err := c.CreateSession(ctx, cfg, route, req)
		assert.NoError(t, err)
		assert.Equal(t, "U1", s.GetUserId())
		assert.True(t, s.GetRefreshDisabled())
	})
	t.Run("jwt", func(t *testing.T) {
		t.Parallel()

		// Set up a mock JWT issuer (publishes OIDC discovery + JWKS).
		idp := mockidp.New(mockidp.Config{})
		issuer := idp.Start(t)

		ctx := testutil.GetContext(t, time.Minute)
		cfg := New(NewDefaultOptions())
		cfg.Options.IdentityProviders = map[string]IdentityProvider{
			"prod": {
				Issuer:        issuer,
				Audiences:     []string{"pomerium.example.com"},
				SupportedAlgs: []string{"ES256"},
			},
		}

		route := &Policy{
			RouteOptions: RouteOptions{
				BearerTokenFormat: nullable.From(config.BearerTokenFormat_BEARER_TOKEN_FORMAT_JWT),
			},
			IdentityProviders: []string{"prod"},
		}

		now := time.Now()
		tok := idp.SignJWT(map[string]any{
			"iss": issuer,
			"sub": "U1",
			"aud": []string{"pomerium.example.com"},
			"exp": now.Add(time.Hour).Unix(),
			"iat": now.Unix(),
			"nbf": now.Unix(),
		})

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://www.example.com", nil)
		require.NoError(t, err)
		req.Header.Set("Authorization", "Bearer "+tok)
		c := NewIncomingIDPTokenSessionCreator(
			noop.NewTracerProvider(),
			func(_ context.Context, _, _ string) (*databroker.Record, error) {
				return nil, storage.ErrNotFound
			},
			func(_ context.Context, records []*databroker.Record) error {
				if assert.Len(t, records, 2, "should put session and user") {
					assert.Equal(t, "type.googleapis.com/session.Session", records[0].Type)
					assert.Equal(t, "type.googleapis.com/user.User", records[1].Type)
				}
				return nil
			},
		)
		s, err := c.CreateSession(ctx, cfg, route, req)
		assert.NoError(t, err)
		assert.Equal(t, "prod/U1", s.GetUserId())
		assert.Equal(t, "prod", s.GetIdpId())
		assert.True(t, s.GetRefreshDisabled())
	})
	t.Run("proxy_protocol", func(t *testing.T) {
		t.Parallel()

		mux := http.NewServeMux()
		mux.HandleFunc("/.pomerium/verify-identity-token", func(w http.ResponseWriter, _ *http.Request) {
			json.NewEncoder(w).Encode(&authenticateapi.VerifyTokenResponse{
				Valid:  true,
				Claims: jwtutil.Claims{"sub": "U1"},
			})
		})
		li, err := net.Listen("tcp", ":0")
		require.NoError(t, err)
		t.Cleanup(func() { _ = li.Close() })
		li = &proxyproto.Listener{
			Listener: li,
			ConnPolicy: func(_ proxyproto.ConnPolicyOptions) (proxyproto.Policy, error) {
				return proxyproto.REQUIRE, nil
			},
		}
		srv := &httptest.Server{
			Listener: li,
			Config:   &http.Server{Handler: mux},
		}
		srv.Start()

		ctx := testutil.GetContext(t, time.Minute)
		cfg := New(NewDefaultOptions())
		cfg.Options.AuthenticateURLString = srv.URL
		cfg.Options.ClientSecret = "CLIENT_SECRET_1"
		cfg.Options.ClientID = "CLIENT_ID_1"
		cfg.Options.BearerTokenFormat = nullable.From(*config.BearerTokenFormat_BEARER_TOKEN_FORMAT_IDP_IDENTITY_TOKEN.Enum())
		cfg.Options.UseProxyProtocol = true
		route := &Policy{}
		route.IDPClientSecret = "CLIENT_SECRET_2"
		route.IDPClientID = "CLIENT_ID_2"
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://www.example.com", nil)
		require.NoError(t, err)
		req.Header.Set("Authorization", "Bearer IDENTITY_TOKEN")
		c := NewIncomingIDPTokenSessionCreator(
			noop.NewTracerProvider(),
			func(_ context.Context, _, _ string) (*databroker.Record, error) {
				return nil, storage.ErrNotFound
			},
			func(_ context.Context, records []*databroker.Record) error {
				if assert.Len(t, records, 2, "should put session and user") {
					assert.Equal(t, "type.googleapis.com/session.Session", records[0].Type)
					assert.Equal(t, "type.googleapis.com/user.User", records[1].Type)
				}
				return nil
			},
		)
		s, err := c.CreateSession(ctx, cfg, route, req)
		assert.NoError(t, err)
		assert.Equal(t, "U1", s.GetUserId())
		assert.True(t, s.GetRefreshDisabled())
	})
}

// TestJWTSingleflightKey checks the de-dup key is keyed on (provider name, raw
// token): the same token under different providers must not collapse, and
// different tokens must not collapse. Audiences are per-provider now, so they
// are no longer part of the key — the provider name already scopes them.
func TestJWTSingleflightKey(t *testing.T) {
	t.Parallel()

	const tok = "header.payload.sig"

	assert.NotEqual(t,
		jwtSingleflightKey("prod", tok),
		jwtSingleflightKey("staging", tok),
		"same token under different providers must not share a key")

	assert.NotEqual(t,
		jwtSingleflightKey("prod", tok),
		jwtSingleflightKey("prod", "other.token.sig"),
		"different tokens must not share a key")

	assert.Equal(t,
		jwtSingleflightKey("prod", tok),
		jwtSingleflightKey("prod", tok),
		"same (provider, token) must be stable")
}

// TestVerifyJWTAndCreateSession exercises the verify-and-create body factored
// out of the singleflight wrapper: provider-namespaced identity, mandatory
// `sub`, per-provider audience binding, the TTL cap, and non-persistence of the
// raw JWT.
func TestVerifyJWTAndCreateSession(t *testing.T) {
	t.Parallel()

	idp := mockidp.New(mockidp.Config{})
	issuer := idp.Start(t)

	ctx := testutil.GetContext(t, time.Minute)
	cfg := New(NewDefaultOptions())
	cfg.Options.CookieExpire = time.Hour // makes the TTL cap observable
	cfg.Options.IdentityProviders = map[string]IdentityProvider{
		"prod": {Issuer: issuer, Audiences: []string{"api-a"}, SupportedAlgs: []string{"ES256"}},
	}
	resolver, err := cfg.IdentityProviderResolver()
	require.NoError(t, err)
	require.NotNil(t, resolver)

	now := time.Now()
	mkToken := func(sub string, aud []string, exp time.Time) string {
		claims := map[string]any{
			"iss": issuer,
			"aud": aud,
			"exp": exp.Unix(),
			"iat": now.Unix(),
			"nbf": now.Unix(),
		}
		if sub != "" {
			claims["sub"] = sub
		}
		return idp.SignJWT(claims)
	}
	newCreator := func() *incomingIDPTokenSessionCreator {
		return NewIncomingIDPTokenSessionCreator(
			noop.NewTracerProvider(),
			func(_ context.Context, _, _ string) (*databroker.Record, error) {
				return nil, storage.ErrNotFound
			},
			func(_ context.Context, _ []*databroker.Record) error { return nil },
		).(*incomingIDPTokenSessionCreator)
	}

	t.Run("happy path sets provider-namespaced identity", func(t *testing.T) {
		c := newCreator()
		c.timeNow = func() time.Time { return now }
		tok := mkToken("U1", []string{"api-a"}, now.Add(time.Hour))
		s, err := c.verifyJWTAndCreateSession(ctx, cfg, resolver, tok)
		require.NoError(t, err)
		assert.Equal(t, "prod", s.GetIdpId())
		assert.Equal(t, "prod/U1", s.GetUserId())
		assert.Equal(t, jwtProviderSessionID("prod", tok), s.GetId())
		assert.True(t, s.GetRefreshDisabled())
		assert.Empty(t, s.GetIdToken().GetRaw(), "raw JWT must not be persisted")
	})

	t.Run("missing sub rejected", func(t *testing.T) {
		c := newCreator()
		tok := mkToken("", []string{"api-a"}, now.Add(time.Hour))
		_, err := c.verifyJWTAndCreateSession(ctx, cfg, resolver, tok)
		assert.ErrorIs(t, err, sessions.ErrInvalidSession)
	})

	t.Run("wrong audience for provider rejected", func(t *testing.T) {
		c := newCreator()
		tok := mkToken("U1", []string{"api-b"}, now.Add(time.Hour))
		_, err := c.verifyJWTAndCreateSession(ctx, cfg, resolver, tok)
		assert.ErrorIs(t, err, sessions.ErrInvalidSession)
	})

	t.Run("ttl capped at now+CookieExpire", func(t *testing.T) {
		c := newCreator()
		c.timeNow = func() time.Time { return now }
		tok := mkToken("U1", []string{"api-a"}, now.Add(100*time.Hour)) // far beyond CookieExpire
		s, err := c.verifyJWTAndCreateSession(ctx, cfg, resolver, tok)
		require.NoError(t, err)
		assert.WithinDuration(t, now.Add(time.Hour), s.GetExpiresAt().AsTime(), time.Second)
	})

	t.Run("ttl uses token exp when earlier than cap", func(t *testing.T) {
		c := newCreator()
		c.timeNow = func() time.Time { return now }
		exp := now.Add(5 * time.Minute)
		tok := mkToken("U1", []string{"api-a"}, exp)
		s, err := c.verifyJWTAndCreateSession(ctx, cfg, resolver, tok)
		require.NoError(t, err)
		assert.WithinDuration(t, exp, s.GetExpiresAt().AsTime(), time.Second)
	})

	// A cached session whose capped TTL has lapsed must NOT be returned stale
	// (authorize would reject it as expired) — it is re-minted, so a still-valid
	// token longer-lived than CookieExpire keeps working.
	t.Run("expired cached session is re-minted", func(t *testing.T) {
		tok := mkToken("U1", []string{"api-a"}, now.Add(100*time.Hour))
		sessionID := jwtProviderSessionID("prod", tok)

		stale := session.New("prod", sessionID)
		stale.UserId = "prod/STALE"
		stale.ExpiresAt = timestamppb.New(now.Add(-time.Hour)) // already lapsed
		anyStale, err := anypb.New(stale)
		require.NoError(t, err)

		c := NewIncomingIDPTokenSessionCreator(
			noop.NewTracerProvider(),
			func(_ context.Context, _, id string) (*databroker.Record, error) {
				if id == sessionID {
					return &databroker.Record{Id: id, Data: anyStale}, nil
				}
				return nil, storage.ErrNotFound
			},
			func(_ context.Context, _ []*databroker.Record) error { return nil },
		).(*incomingIDPTokenSessionCreator)
		c.timeNow = func() time.Time { return now }

		s, err := c.verifyJWTAndCreateSession(ctx, cfg, resolver, tok)
		require.NoError(t, err)
		assert.True(t, s.GetExpiresAt().AsTime().After(now), "re-minted session must have a future expiry")
		assert.Equal(t, "prod/U1", s.GetUserId(), "must re-mint, not return the stale cached session")
	})
}

// TestCreateSessionForJWT_RouteProviderScoping verifies the route's
// identity_providers allowlist is enforced (on the unverified issuer, before
// verification): a route allowing only idp-a rejects an idp-b token, while a
// route with an empty allowlist accepts any configured provider.
func TestCreateSessionForJWT_RouteProviderScoping(t *testing.T) {
	t.Parallel()

	idpA := mockidp.New(mockidp.Config{})
	issuerA := idpA.Start(t)
	idpB := mockidp.New(mockidp.Config{})
	issuerB := idpB.Start(t)

	ctx := testutil.GetContext(t, time.Minute)
	cfg := New(NewDefaultOptions())
	cfg.Options.IdentityProviders = map[string]IdentityProvider{
		"idp-a": {Issuer: issuerA, Audiences: []string{"api"}, SupportedAlgs: []string{"ES256"}},
		"idp-b": {Issuer: issuerB, Audiences: []string{"api"}, SupportedAlgs: []string{"ES256"}},
	}

	now := time.Now()
	tokB := idpB.SignJWT(map[string]any{
		"iss": issuerB,
		"sub": "svc",
		"aud": []string{"api"},
		"exp": now.Add(time.Hour).Unix(),
		"iat": now.Unix(),
		"nbf": now.Unix(),
	})

	newCreator := func() *incomingIDPTokenSessionCreator {
		return NewIncomingIDPTokenSessionCreator(
			noop.NewTracerProvider(),
			func(_ context.Context, _, _ string) (*databroker.Record, error) {
				return nil, storage.ErrNotFound
			},
			func(_ context.Context, _ []*databroker.Record) error { return nil },
		).(*incomingIDPTokenSessionCreator)
	}
	mkReq := func() *http.Request {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://www.example.com", nil)
		require.NoError(t, err)
		req.Header.Set("Authorization", "Bearer "+tokB)
		return req
	}
	jwtRoute := func(providers ...string) *Policy {
		return &Policy{
			RouteOptions:      RouteOptions{BearerTokenFormat: nullable.From(config.BearerTokenFormat_BEARER_TOKEN_FORMAT_JWT)},
			IdentityProviders: providers,
		}
	}

	t.Run("route allowing only idp-a rejects idp-b token", func(t *testing.T) {
		_, err := newCreator().CreateSession(ctx, cfg, jwtRoute("idp-a"), mkReq())
		assert.ErrorIs(t, err, sessions.ErrInvalidSession)
	})

	t.Run("route with empty allowlist accepts idp-b token", func(t *testing.T) {
		s, err := newCreator().CreateSession(ctx, cfg, jwtRoute(), mkReq())
		require.NoError(t, err)
		assert.Equal(t, "idp-b/svc", s.GetUserId())
		assert.Equal(t, "idp-b", s.GetIdpId())
	})
}
