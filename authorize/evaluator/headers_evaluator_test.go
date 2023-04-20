package evaluator

import (
	"context"
	"math"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v3/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/structpb"

	"github.com/pomerium/pomerium/authorize/internal/store"
	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/pkg/cryptutil"
	"github.com/pomerium/pomerium/pkg/grpc/session"
	"github.com/pomerium/pomerium/pkg/storage"
)

func TestNewHeadersRequestFromPolicy(t *testing.T) {
	req := NewHeadersRequestFromPolicy(&config.Policy{
		EnableGoogleCloudServerlessAuthentication: true,
		From: "https://from.example.com",
		To: config.WeightedURLs{
			{
				URL: *mustParseURL("http://to.example.com"),
			},
		},
	})
	assert.Equal(t, &HeadersRequest{
		EnableGoogleCloudServerlessAuthentication: true,
		Issuer:     "from.example.com",
		ToAudience: "https://to.example.com",
	}, req)
}

func TestHeadersEvaluator(t *testing.T) {
	type A = []interface{}
	type M = map[string]interface{}

	signingKey, err := cryptutil.NewSigningKey()
	require.NoError(t, err)
	encodedSigningKey, err := cryptutil.EncodePrivateKey(signingKey)
	require.NoError(t, err)
	privateJWK, err := cryptutil.PrivateJWKFromBytes(encodedSigningKey)
	require.NoError(t, err)
	publicJWK, err := cryptutil.PublicJWKFromBytes(encodedSigningKey)
	require.NoError(t, err)

	eval := func(t *testing.T, data []proto.Message, input *HeadersRequest) (*HeadersResponse, error) {
		ctx := context.Background()
		ctx = storage.WithQuerier(ctx, storage.NewStaticQuerier(data...))
		store := store.New()
		store.UpdateJWTClaimHeaders(config.NewJWTClaimHeaders("email", "groups", "user", "CUSTOM_KEY"))
		store.UpdateSigningKey(privateJWK)
		e, err := NewHeadersEvaluator(ctx, store)
		require.NoError(t, err)
		return e.Evaluate(ctx, input)
	}

	t.Run("jwt", func(t *testing.T) {
		output, err := eval(t,
			[]proto.Message{
				&session.Session{Id: "s1", ImpersonateSessionId: proto.String("s2"), UserId: "u1"},
				&session.Session{Id: "s2", UserId: "u2", Claims: map[string]*structpb.ListValue{
					"name": {Values: []*structpb.Value{
						structpb.NewStringValue("n1"),
					}},
				}},
			},
			&HeadersRequest{
				Issuer:     "from.example.com",
				ToAudience: "to.example.com",
				Session: RequestSession{
					ID: "s1",
				},
			})
		require.NoError(t, err)

		rawJWT, err := jwt.ParseSigned(output.Headers.Get("X-Pomerium-Jwt-Assertion"))
		require.NoError(t, err)

		var claims M
		err = rawJWT.Claims(publicJWK, &claims)
		require.NoError(t, err)

		assert.Equal(t, claims["iss"], "from.example.com")
		assert.Equal(t, claims["aud"], "from.example.com")
		assert.Equal(t, claims["exp"], math.Round(claims["exp"].(float64)))
		assert.LessOrEqual(t, claims["exp"], float64(time.Now().Add(time.Minute*6).Unix()),
			"JWT should expire within 5 minutes, but got: %v", claims["exp"])
		assert.Equal(t, "s1", claims["sid"], "should set session id to input session id")
		assert.Equal(t, "u2", claims["sub"], "should set subject to user id")
		assert.Equal(t, "u2", claims["user"], "should set user to user id")
		assert.Equal(t, "n1", claims["name"], "should set name")
	})

	t.Run("access token", func(t *testing.T) {
		output, err := eval(t,
			[]proto.Message{
				&session.Session{Id: "s1", OauthToken: &session.OAuthToken{
					AccessToken: "ACCESS_TOKEN",
				}},
			},
			&HeadersRequest{
				Issuer:          "from.example.com",
				ToAudience:      "to.example.com",
				Session:         RequestSession{ID: "s1"},
				PassAccessToken: true,
			})
		require.NoError(t, err)

		assert.Equal(t, "Bearer ACCESS_TOKEN", output.Headers.Get("Authorization"))
	})

	t.Run("id token", func(t *testing.T) {
		output, err := eval(t,
			[]proto.Message{
				&session.Session{Id: "s1", IdToken: &session.IDToken{
					Raw: "ID_TOKEN",
				}},
			},
			&HeadersRequest{
				Issuer:      "from.example.com",
				ToAudience:  "to.example.com",
				Session:     RequestSession{ID: "s1"},
				PassIDToken: true,
			})
		require.NoError(t, err)

		assert.Equal(t, "Bearer ID_TOKEN", output.Headers.Get("Authorization"))
	})
}
