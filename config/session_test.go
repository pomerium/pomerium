package config

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/trace/noop"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/testing/protocmp"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/pomerium/pomerium/internal/encoding/jws"
	"github.com/pomerium/pomerium/internal/httputil"
	"github.com/pomerium/pomerium/internal/jwtutil"
	"github.com/pomerium/pomerium/internal/sessions"
	"github.com/pomerium/pomerium/internal/testutil"
	"github.com/pomerium/pomerium/internal/urlutil"
	"github.com/pomerium/pomerium/pkg/authenticateapi"
	"github.com/pomerium/pomerium/pkg/cryptutil"
	"github.com/pomerium/pomerium/pkg/grpc/databroker"
	identitypb "github.com/pomerium/pomerium/pkg/grpc/identity"
	"github.com/pomerium/pomerium/pkg/grpc/session"
	"github.com/pomerium/pomerium/pkg/grpc/user"
	"github.com/pomerium/pomerium/pkg/identity"
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
		h, err := store.LoadSessionHandleAndCheckIDP(r)
		assert.ErrorIs(t, err, sessions.ErrNoSessionFound)
		assert.Nil(t, h)
	})
	t.Run("query", func(t *testing.T) {
		rawJWS := makeJWS(t, &session.Handle{
			Iss:                proto.String("authenticate.example.com"),
			Id:                 "example",
			IdentityProviderId: idp2.GetId(),
		})

		r, err := http.NewRequest(http.MethodGet, "https://p1.example.com?"+url.Values{
			urlutil.QuerySession: {rawJWS},
		}.Encode(), nil)
		require.NoError(t, err)
		h, err := store.LoadSessionHandleAndCheckIDP(r)
		assert.NoError(t, err)
		assert.Empty(t, cmp.Diff(&session.Handle{
			Iss:                proto.String("authenticate.example.com"),
			Id:                 "example",
			IdentityProviderId: idp2.GetId(),
		}, h, protocmp.Transform()))
	})
	t.Run("header", func(t *testing.T) {
		rawJWS := makeJWS(t, &session.Handle{
			Iss:                proto.String("authenticate.example.com"),
			Id:                 "example",
			IdentityProviderId: idp3.GetId(),
		})

		r, err := http.NewRequest(http.MethodGet, "https://p2.example.com", nil)
		require.NoError(t, err)
		r.Header.Set(httputil.HeaderPomeriumAuthorization, rawJWS)
		h, err := store.LoadSessionHandleAndCheckIDP(r)
		assert.NoError(t, err)
		assert.Empty(t, cmp.Diff(&session.Handle{
			Iss:                proto.String("authenticate.example.com"),
			Id:                 "example",
			IdentityProviderId: idp3.GetId(),
		}, h, protocmp.Transform()))
	})
	t.Run("wrong idp", func(t *testing.T) {
		rawJWS := makeJWS(t, &session.Handle{
			Iss:                proto.String("authenticate.example.com"),
			Id:                 "example",
			IdentityProviderId: idp1.GetId(),
		})

		r, err := http.NewRequest(http.MethodGet, "https://p2.example.com", nil)
		require.NoError(t, err)
		r.Header.Set(httputil.HeaderPomeriumAuthorization, rawJWS)
		h, err := store.LoadSessionHandleAndCheckIDP(r)
		assert.Error(t, err)
		assert.Nil(t, h)
	})
	t.Run("blank idp", func(t *testing.T) {
		rawJWS := makeJWS(t, &session.Handle{
			Iss: proto.String("authenticate.example.com"),
			Id:  "example",
		})

		r, err := http.NewRequest(http.MethodGet, "https://p2.example.com", nil)
		require.NoError(t, err)
		r.Header.Set(httputil.HeaderPomeriumAuthorization, rawJWS)
		h, err := store.LoadSessionHandleAndCheckIDP(r)
		assert.NoError(t, err)
		assert.Empty(t, cmp.Diff(&session.Handle{
			Iss: proto.String("authenticate.example.com"),
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
}

func TestGetIncomingIDPAccessTokenForPolicy(t *testing.T) {
	t.Parallel()

	bearerTokenFormatIDPAccessToken := BearerTokenFormatIDPAccessToken

	for _, tc := range []struct {
		name                    string
		globalBearerTokenFormat *BearerTokenFormat
		routeBearerTokenFormat  *BearerTokenFormat
		headers                 http.Header
		expectedOK              bool
		expectedToken           string
	}{
		{
			name:       "empty headers",
			expectedOK: false,
		},
		{
			name:       "bearer disabled",
			headers:    http.Header{"Authorization": {"Bearer access token via bearer"}},
			expectedOK: false,
		},
		{
			name:                    "bearer enabled via options",
			globalBearerTokenFormat: &bearerTokenFormatIDPAccessToken,
			headers:                 http.Header{"Authorization": {"Bearer access token via bearer"}},
			expectedOK:              true,
			expectedToken:           "access token via bearer",
		},
		{
			name:                   "bearer enabled via route",
			routeBearerTokenFormat: &bearerTokenFormatIDPAccessToken,
			headers:                http.Header{"Authorization": {"Bearer access token via bearer"}},
			expectedOK:             true,
			expectedToken:          "access token via bearer",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			cfg := &Config{
				Options: NewDefaultOptions(),
			}
			cfg.Options.BearerTokenFormat = tc.globalBearerTokenFormat

			var route *Policy
			if tc.routeBearerTokenFormat != nil {
				route = &Policy{
					BearerTokenFormat: tc.routeBearerTokenFormat,
				}
			}

			r, err := http.NewRequest(http.MethodGet, "https://example.com", nil)
			require.NoError(t, err)
			if tc.headers != nil {
				r.Header = tc.headers
			}

			actualToken, actualOK := cfg.GetIncomingIDPAccessTokenForPolicy(route, r)
			assert.Equal(t, tc.expectedOK, actualOK)
			assert.Equal(t, tc.expectedToken, actualToken)
		})
	}
}

func TestGetIncomingIDPIdentityTokenForPolicy(t *testing.T) {
	t.Parallel()

	bearerTokenFormatIDPIdentityToken := BearerTokenFormatIDPIdentityToken

	for _, tc := range []struct {
		name                    string
		globalBearerTokenFormat *BearerTokenFormat
		routeBearerTokenFormat  *BearerTokenFormat
		headers                 http.Header
		expectedOK              bool
		expectedToken           string
	}{
		{
			name:       "empty headers",
			expectedOK: false,
		},
		{
			name:       "bearer disabled",
			headers:    http.Header{"Authorization": {"Bearer identity token via bearer"}},
			expectedOK: false,
		},
		{
			name:                    "bearer enabled via options",
			globalBearerTokenFormat: &bearerTokenFormatIDPIdentityToken,
			headers:                 http.Header{"Authorization": {"Bearer identity token via bearer"}},
			expectedOK:              true,
			expectedToken:           "identity token via bearer",
		},
		{
			name:                   "bearer enabled via route",
			routeBearerTokenFormat: &bearerTokenFormatIDPIdentityToken,
			headers:                http.Header{"Authorization": {"Bearer identity token via bearer"}},
			expectedOK:             true,
			expectedToken:          "identity token via bearer",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			cfg := &Config{
				Options: NewDefaultOptions(),
			}
			cfg.Options.BearerTokenFormat = tc.globalBearerTokenFormat

			var route *Policy
			if tc.routeBearerTokenFormat != nil {
				route = &Policy{
					BearerTokenFormat: tc.routeBearerTokenFormat,
				}
			}

			r, err := http.NewRequest(http.MethodGet, "https://example.com", nil)
			require.NoError(t, err)
			if tc.headers != nil {
				r.Header = tc.headers
			}

			actualToken, actualOK := cfg.GetIncomingIDPIdentityTokenForPolicy(route, r)
			assert.Equal(t, tc.expectedOK, actualOK)
			assert.Equal(t, tc.expectedToken, actualToken)
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

			cfg := &Config{Options: NewDefaultOptions()}
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
		cfg := &Config{Options: NewDefaultOptions()}
		cfg.Options.AuthenticateURLString = srv.URL
		cfg.Options.ClientSecret = "CLIENT_SECRET_1"
		cfg.Options.ClientID = "CLIENT_ID_1"
		bearerTokenFormatIDPAccessToken := BearerTokenFormatIDPAccessToken
		cfg.Options.BearerTokenFormat = &bearerTokenFormatIDPAccessToken
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
		cfg := &Config{Options: NewDefaultOptions()}
		cfg.Options.AuthenticateURLString = srv.URL
		cfg.Options.ClientSecret = "CLIENT_SECRET_1"
		cfg.Options.ClientID = "CLIENT_ID_1"
		bearerTokenFormatIDPIdentityToken := BearerTokenFormatIDPIdentityToken
		cfg.Options.BearerTokenFormat = &bearerTokenFormatIDPIdentityToken
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
