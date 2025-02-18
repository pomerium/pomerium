package config

import (
	"encoding/base64"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/pomerium/pomerium/internal/encoding/jws"
	"github.com/pomerium/pomerium/internal/httputil"
	"github.com/pomerium/pomerium/internal/jwtutil"
	"github.com/pomerium/pomerium/internal/sessions"
	"github.com/pomerium/pomerium/internal/testutil"
	"github.com/pomerium/pomerium/internal/urlutil"
	"github.com/pomerium/pomerium/pkg/cryptutil"
	"github.com/pomerium/pomerium/pkg/grpc/session"
	"github.com/pomerium/pomerium/pkg/grpc/user"
	"github.com/pomerium/pomerium/pkg/identity"
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

	makeJWS := func(t *testing.T, state *sessions.State) string {
		e, err := jws.NewHS256Signer(sharedKey)
		require.NoError(t, err)

		rawJWS, err := e.Marshal(state)
		require.NoError(t, err)

		return string(rawJWS)
	}

	t.Run("mssing", func(t *testing.T) {
		r, err := http.NewRequest(http.MethodGet, "https://p1.example.com", nil)
		require.NoError(t, err)
		s, err := store.LoadSessionStateAndCheckIDP(r)
		assert.ErrorIs(t, err, sessions.ErrNoSessionFound)
		assert.Nil(t, s)
	})
	t.Run("query", func(t *testing.T) {
		rawJWS := makeJWS(t, &sessions.State{
			Issuer:             "authenticate.example.com",
			ID:                 "example",
			IdentityProviderID: idp2.GetId(),
		})

		r, err := http.NewRequest(http.MethodGet, "https://p1.example.com?"+url.Values{
			urlutil.QuerySession: {rawJWS},
		}.Encode(), nil)
		require.NoError(t, err)
		s, err := store.LoadSessionStateAndCheckIDP(r)
		assert.NoError(t, err)
		assert.Empty(t, cmp.Diff(&sessions.State{
			Issuer:             "authenticate.example.com",
			ID:                 "example",
			IdentityProviderID: idp2.GetId(),
		}, s))
	})
	t.Run("header", func(t *testing.T) {
		rawJWS := makeJWS(t, &sessions.State{
			Issuer:             "authenticate.example.com",
			ID:                 "example",
			IdentityProviderID: idp3.GetId(),
		})

		r, err := http.NewRequest(http.MethodGet, "https://p2.example.com", nil)
		require.NoError(t, err)
		r.Header.Set(httputil.HeaderPomeriumAuthorization, rawJWS)
		s, err := store.LoadSessionStateAndCheckIDP(r)
		assert.NoError(t, err)
		assert.Empty(t, cmp.Diff(&sessions.State{
			Issuer:             "authenticate.example.com",
			ID:                 "example",
			IdentityProviderID: idp3.GetId(),
		}, s))
	})
	t.Run("wrong idp", func(t *testing.T) {
		rawJWS := makeJWS(t, &sessions.State{
			Issuer:             "authenticate.example.com",
			ID:                 "example",
			IdentityProviderID: idp1.GetId(),
		})

		r, err := http.NewRequest(http.MethodGet, "https://p2.example.com", nil)
		require.NoError(t, err)
		r.Header.Set(httputil.HeaderPomeriumAuthorization, rawJWS)
		s, err := store.LoadSessionStateAndCheckIDP(r)
		assert.Error(t, err)
		assert.Nil(t, s)
	})
	t.Run("blank idp", func(t *testing.T) {
		rawJWS := makeJWS(t, &sessions.State{
			Issuer: "authenticate.example.com",
			ID:     "example",
		})

		r, err := http.NewRequest(http.MethodGet, "https://p2.example.com", nil)
		require.NoError(t, err)
		r.Header.Set(httputil.HeaderPomeriumAuthorization, rawJWS)
		s, err := store.LoadSessionStateAndCheckIDP(r)
		assert.NoError(t, err)
		assert.Empty(t, cmp.Diff(&sessions.State{
			Issuer: "authenticate.example.com",
			ID:     "example",
		}, s))
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
	assert.Equal(t, "c58990ec-85d4-5054-b27f-e7c5d9c602c5", getAccessTokenSessionID(&Policy{
		From:     "https://from.example.com",
		Response: &DirectResponse{Status: 204},
	}, "TOKEN"))
	assert.Equal(t, "4dff4540-493b-502a-bdec-2f346e6e480d", getIdentityTokenSessionID(&Policy{
		From:     "https://from.example.com",
		Response: &DirectResponse{Status: 204},
	}, "TOKEN"))
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
			name:          "custom header",
			headers:       http.Header{"X-Pomerium-Idp-Access-Token": {"access token via custom header"}},
			expectedOK:    true,
			expectedToken: "access token via custom header",
		},
		{
			name:          "custom authorization",
			headers:       http.Header{"Authorization": {"Pomerium-Idp-Access-Token access token via custom authorization"}},
			expectedOK:    true,
			expectedToken: "access token via custom authorization",
		},
		{
			name:          "custom bearer",
			headers:       http.Header{"Authorization": {"Bearer Pomerium-Idp-Access-Token-access token via custom bearer"}},
			expectedOK:    true,
			expectedToken: "access token via custom bearer",
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
			name:          "custom header",
			headers:       http.Header{"X-Pomerium-Idp-Identity-Token": {"identity token via custom header"}},
			expectedOK:    true,
			expectedToken: "identity token via custom header",
		},
		{
			name:          "custom authorization",
			headers:       http.Header{"Authorization": {"Pomerium-Idp-Identity-Token identity token via custom authorization"}},
			expectedOK:    true,
			expectedToken: "identity token via custom authorization",
		},
		{
			name:          "custom bearer",
			headers:       http.Header{"Authorization": {"Bearer Pomerium-Idp-Identity-Token-identity token via custom bearer"}},
			expectedOK:    true,
			expectedToken: "identity token via custom bearer",
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
				Id:         "S1",
				AccessedAt: timestamppb.New(tm1),
				ExpiresAt:  timestamppb.New(tm1.Add(time.Hour * 14)),
				IssuedAt:   timestamppb.New(tm1),
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
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			cfg := &Config{Options: NewDefaultOptions()}
			c := &incomingIDPTokenSessionCreator{
				timeNow: func() time.Time { return tm1 },
			}
			actual := c.newSessionFromIDPClaims(cfg, tc.sessionID, tc.claims)
			testutil.AssertProtoEqual(t, tc.expect, actual)
		})
	}
}

func Test_newUserFromIDPClaims(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name   string
		claims jwtutil.Claims
		expect *user.User
	}{
		{"empty claims", nil, &user.User{}},
		{"full claims", jwtutil.Claims{
			"sub":   "USER_ID",
			"name":  "NAME",
			"email": "EMAIL",
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

			actual := new(incomingIDPTokenSessionCreator).newUserFromIDPClaims(tc.claims)
			testutil.AssertProtoEqual(t, tc.expect, actual)
		})
	}
}
