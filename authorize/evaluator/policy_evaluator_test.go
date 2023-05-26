package evaluator

import (
	"context"
	"math"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/pkg/cryptutil"
	"github.com/pomerium/pomerium/pkg/grpc/session"
	"github.com/pomerium/pomerium/pkg/grpc/user"
	"github.com/pomerium/pomerium/pkg/policy"
	"github.com/pomerium/pomerium/pkg/policy/criteria"
)

func TestPolicyEvaluator(t *testing.T) {
	signingKey, err := cryptutil.NewSigningKey()
	require.NoError(t, err)
	encodedSigningKey, err := cryptutil.EncodePrivateKey(signingKey)
	require.NoError(t, err)
	privateJWK, err := cryptutil.PrivateJWKFromBytes(encodedSigningKey)
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
			Allow: NewRuleResult(true, criteria.ReasonEmailOK),
			Deny:  NewRuleResult(false, criteria.ReasonValidClientCertificateOrNoneRequired),
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
			Allow: NewRuleResult(true, criteria.ReasonEmailOK),
			Deny:  NewRuleResult(true, criteria.ReasonInvalidClientCertificate),
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
			Allow: NewRuleResult(false, criteria.ReasonEmailUnauthorized, criteria.ReasonUserUnauthorized),
			Deny:  NewRuleResult(false, criteria.ReasonValidClientCertificateOrNoneRequired),
		}, output)
	})
	t.Run("ppl", func(t *testing.T) {
		t.Run("allow", func(t *testing.T) {
			rego, err := policy.GenerateRegoFromReader(strings.NewReader(`
- allow:
    and:
      - accept: 1
`))
			require.NoError(t, err)
			p := &config.Policy{
				From: "https://from.example.com",
				To:   config.WeightedURLs{{URL: *mustParseURL("https://to.example.com")}},
				SubPolicies: []config.SubPolicy{
					{Rego: []string{rego}},
				},
			}
			output, err := eval(t,
				p,
				[]proto.Message{s1, u1, s2, u2},
				&PolicyRequest{
					HTTP:    RequestHTTP{Method: "GET", URL: "https://from.example.com/path"},
					Session: RequestSession{ID: "s1"},

					IsValidClientCertificate: true,
				})
			require.NoError(t, err)
			assert.Equal(t, &PolicyResponse{
				Allow: NewRuleResult(true, criteria.ReasonAccept),
				Deny:  NewRuleResult(false, criteria.ReasonValidClientCertificateOrNoneRequired),
			}, output)
		})
		t.Run("deny", func(t *testing.T) {
			rego, err := policy.GenerateRegoFromReader(strings.NewReader(`
- deny:
    and:
      - accept: 1
`))
			require.NoError(t, err)
			p := &config.Policy{
				From: "https://from.example.com",
				To:   config.WeightedURLs{{URL: *mustParseURL("https://to.example.com")}},
				SubPolicies: []config.SubPolicy{
					{Rego: []string{rego}},
				},
			}
			output, err := eval(t,
				p,
				[]proto.Message{s1, u1, s2, u2},
				&PolicyRequest{
					HTTP:    RequestHTTP{Method: "GET", URL: "https://from.example.com/path"},
					Session: RequestSession{ID: "s1"},

					IsValidClientCertificate: true,
				})
			require.NoError(t, err)
			assert.Equal(t, &PolicyResponse{
				Allow: NewRuleResult(false),
				Deny:  NewRuleResult(true, criteria.ReasonAccept),
			}, output)
		})
		t.Run("client certificate", func(t *testing.T) {
			rego, err := policy.GenerateRegoFromReader(strings.NewReader(`
- deny:
    and:
      - invalid_client_certificate: 1
      - accept: 1
`))
			require.NoError(t, err)
			p := &config.Policy{
				From: "https://from.example.com",
				To:   config.WeightedURLs{{URL: *mustParseURL("https://to.example.com")}},
				SubPolicies: []config.SubPolicy{
					{Rego: []string{rego}},
				},
			}
			output, err := eval(t,
				p,
				[]proto.Message{s1, u1, s2, u2},
				&PolicyRequest{
					HTTP:    RequestHTTP{Method: "GET", URL: "https://from.example.com/path"},
					Session: RequestSession{ID: "s1"},

					IsValidClientCertificate: false,
				})
			require.NoError(t, err)
			assert.Equal(t, &PolicyResponse{
				Allow: NewRuleResult(false),
				Deny:  NewRuleResult(true, criteria.ReasonAccept, criteria.ReasonInvalidClientCertificate),
			}, output)
		})
	})
}
