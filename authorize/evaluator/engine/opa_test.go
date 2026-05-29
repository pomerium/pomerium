package engine

import (
	"net/http"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pomerium/pomerium/authorize/evaluator"
	"github.com/pomerium/pomerium/authorize/internal/store"
	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/pkg/cryptutil"
	"github.com/pomerium/pomerium/pkg/grpc/session"
	"github.com/pomerium/pomerium/pkg/grpc/user"
	"github.com/pomerium/pomerium/pkg/policy/criteria"
	"github.com/pomerium/pomerium/pkg/storage"
)

func TestNewOPA(t *testing.T) {
	t.Parallel()

	t.Run("nil inner", func(t *testing.T) {
		t.Parallel()
		_, err := NewOPA(nil)
		assert.ErrorIs(t, err, ErrNilEvaluator)
	})

	t.Run("ok", func(t *testing.T) {
		t.Parallel()
		inner := newTestInnerEvaluator(t, nil)
		e, err := NewOPA(inner)
		require.NoError(t, err)
		assert.NotNil(t, e)
		assert.NoError(t, e.Close())
	})
}

func TestOPAEngine_Evaluate(t *testing.T) {
	t.Parallel()

	policy := &config.Policy{
		From:         "https://from.example.com",
		To:           config.WeightedURLs{{URL: mustParseURL(t, "https://to.example.com")}},
		AllowedUsers: []string{"u1@example.com"},
	}
	s1 := &session.Session{Id: "s1", UserId: "u1"}
	s2 := &session.Session{Id: "s2", UserId: "u2"}
	u1 := &user.User{Id: "u1", Email: "u1@example.com"}
	u2 := &user.User{Id: "u2", Email: "u2@example.com"}

	cases := []struct {
		name      string
		sessionID string
		wantAllow bool
	}{
		{name: "allowed user", sessionID: "s1", wantAllow: true},
		{name: "forbidden user", sessionID: "s2", wantAllow: false},
	}

	for i := range cases {
		c := &cases[i]
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()

			inner := newTestInnerEvaluator(t, []*config.Policy{policy})
			e, err := NewOPA(inner)
			require.NoError(t, err)

			ctx := storage.WithQuerier(t.Context(), storage.NewStaticQuerier(s1, u1, s2, u2))
			dec, err := e.Evaluate(ctx, &evaluator.Request{
				Policy:  policy,
				HTTP:    evaluator.RequestHTTP{Method: http.MethodGet, URL: "https://from.example.com/path"},
				Session: evaluator.RequestSession{ID: c.sessionID},
			})
			require.NoError(t, err)
			require.NotNil(t, dec)
			assert.Equal(t, c.wantAllow, dec.Allow.Value, "Allow")
			assert.False(t, dec.Deny.Value, "Deny should be false in both cases")
		})
	}
}

// TestOPAEngine_Evaluate_RouteNotFound exercises the path where Pomerium has
// no matching route. Without an entry in the inner evaluator the policy
// is denied with ReasonRouteNotFound.
func TestOPAEngine_Evaluate_RouteNotFound(t *testing.T) {
	t.Parallel()

	inner := newTestInnerEvaluator(t, nil)
	e, err := NewOPA(inner)
	require.NoError(t, err)

	dec, err := e.Evaluate(t.Context(), &evaluator.Request{
		Policy: nil,
		HTTP:   evaluator.RequestHTTP{Method: http.MethodGet, URL: "https://x"},
	})
	require.NoError(t, err)
	require.NotNil(t, dec)
	assert.True(t, dec.Deny.Value)
	assert.True(t, dec.Deny.Reasons.Has(criteria.ReasonRouteNotFound))
}

// newTestInnerEvaluator builds a real *evaluator.Evaluator suitable for
// adapter tests. Policies may be nil.
func newTestInnerEvaluator(t *testing.T, policies []*config.Policy) *evaluator.Evaluator {
	t.Helper()

	signingKey, err := cryptutil.NewSigningKey()
	require.NoError(t, err)
	encoded, err := cryptutil.EncodePrivateKey(signingKey)
	require.NoError(t, err)

	ctx := storage.WithQuerier(t.Context(), storage.NewStaticQuerier())
	s := store.New()
	s.UpdateJWTClaimHeaders(config.NewJWTClaimHeaders("email", "groups", "user"))

	opts := []evaluator.Option{evaluator.WithSigningKey(encoded)}
	if len(policies) > 0 {
		opts = append(opts, evaluator.WithPolicies(policies))
	}
	e, err := evaluator.New(ctx, s, nil, opts...)
	require.NoError(t, err)
	return e
}

// mustParseURL parses str or fails the test.
func mustParseURL(t *testing.T, str string) url.URL {
	t.Helper()
	u, err := url.Parse(str)
	require.NoError(t, err)
	return *u
}

// Compile-time assertion: *OPAEngine satisfies PolicyEngine.
var _ PolicyEngine = (*OPAEngine)(nil)
