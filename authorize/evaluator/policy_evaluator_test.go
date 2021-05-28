package evaluator

import (
	"context"
	"math"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
	"gopkg.in/square/go-jose.v2"

	"github.com/pomerium/pomerium/pkg/grpc/session"
	"github.com/pomerium/pomerium/pkg/grpc/user"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/pkg/cryptutil"
)

func TestPolicyEvaluator(t *testing.T) {
	type A = []interface{}
	type M = map[string]interface{}

	signingKey, err := cryptutil.NewSigningKey()
	require.NoError(t, err)
	encodedSigningKey, err := cryptutil.EncodePrivateKey(signingKey)
	require.NoError(t, err)
	privateJWK, err := cryptutil.PrivateJWKFromBytes(encodedSigningKey, jose.ES256)
	require.NoError(t, err)

	eval := func(t *testing.T, policy *config.Policy, data []proto.Message, input *PolicyRequest) (*PolicyResponse, error) {
		store := NewStoreFromProtos(math.MaxUint64, data...)
		store.UpdateIssuer("authenticate.example.com")
		store.UpdateJWTClaimHeaders(config.NewJWTClaimHeaders("email", "groups", "user", "CUSTOM_KEY"))
		store.UpdateSigningKey(privateJWK)
		e, err := NewPolicyEvaluator(context.Background(), store, policy)
		require.NoError(t, err)
		return e.Evaluate(context.Background(), input)
	}

	p1 := &config.Policy{
		From:         "https://from.example.com",
		To:           config.WeightedURLs{{URL: *mustParseURL("https://to.example.com")}},
		AllowedUsers: []string{"u1@example.com"},
	}
	s1 := &session.Session{
		Id:     "s1",
		UserId: "u1",
	}
	s2 := &session.Session{
		Id:     "s2",
		UserId: "u2",
	}
	u1 := &user.User{
		Id:    "u1",
		Email: "u1@example.com",
	}
	u2 := &user.User{
		Id:    "u2",
		Email: "u2@example.com",
	}

	t.Run("allowed", func(t *testing.T) {
		output, err := eval(t,
			p1,
			[]proto.Message{s1, u1, s2, u2},
			&PolicyRequest{
				HTTP:    RequestHTTP{Method: "GET", URL: "https://from.example.com/path"},
				Session: RequestSession{ID: "s1"},

				IsValidClientCertificate: true,
			})
		require.NoError(t, err)
		assert.Equal(t, &PolicyResponse{
			Allow: true,
		}, output)
	})
	t.Run("invalid cert", func(t *testing.T) {
		output, err := eval(t,
			p1,
			[]proto.Message{s1, u1, s2, u2},
			&PolicyRequest{
				HTTP:    RequestHTTP{Method: "GET", URL: "https://from.example.com/path"},
				Session: RequestSession{ID: "s1"},

				IsValidClientCertificate: false,
			})
		require.NoError(t, err)
		assert.Equal(t, &PolicyResponse{
			Allow: true,
			Deny: &Denial{
				Status:  495,
				Message: "invalid client certificate",
			},
		}, output)
	})
	t.Run("forbidden", func(t *testing.T) {
		output, err := eval(t,
			p1,
			[]proto.Message{s1, u1, s2, u2},
			&PolicyRequest{
				HTTP:    RequestHTTP{Method: "GET", URL: "https://from.example.com/path"},
				Session: RequestSession{ID: "s2"},

				IsValidClientCertificate: true,
			})
		require.NoError(t, err)
		assert.Equal(t, &PolicyResponse{
			Allow: false,
		}, output)
	})
}
