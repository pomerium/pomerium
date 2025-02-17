package config

import (
	"encoding/base64"
	"net/http"
	"net/url"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pomerium/pomerium/internal/encoding/jws"
	"github.com/pomerium/pomerium/internal/httputil"
	"github.com/pomerium/pomerium/internal/sessions"
	"github.com/pomerium/pomerium/internal/urlutil"
	"github.com/pomerium/pomerium/pkg/cryptutil"
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
