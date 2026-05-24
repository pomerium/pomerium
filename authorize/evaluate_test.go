package authorize

import (
	"context"
	"errors"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pomerium/pomerium/authorize/evaluator"
	"github.com/pomerium/pomerium/authorize/evaluator/engine"
	"github.com/pomerium/pomerium/authorize/internal/store"
	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/pkg/policy/criteria"
)

// stubEngine is a test PolicyEngine that returns a pre-canned decision
// and exposes the request it was asked to evaluate so tests can assert
// on the inputs the orchestrator passed in.
type stubEngine struct {
	dec     *engine.Decision
	err     error
	gotReq  *evaluator.Request
	closeOk bool
}

func (s *stubEngine) Evaluate(_ context.Context, req *evaluator.Request) (*engine.Decision, error) {
	s.gotReq = req
	return s.dec, s.err
}

func (s *stubEngine) Close() error {
	s.closeOk = true
	return nil
}

// newTestAuthorize builds an *Authorize with a real OPA-backed
// evaluator/headers pipeline and a swappable PolicyEngine, suitable for
// driving the engine-aware orchestrator in unit tests.
func newTestAuthorize(t *testing.T, opt *config.Options, eng engine.PolicyEngine) *Authorize {
	t.Helper()

	a := &Authorize{}
	a.currentConfig.Store(config.New(opt))
	a.store = store.New()
	a.state.Store(new(authorizeState))

	pe, err := newPolicyEvaluator(t.Context(), opt, a.store, nil)
	require.NoError(t, err)

	st := a.state.Load()
	st.evaluator = pe
	st.headers = pe.HeadersEvaluator()
	st.engine = eng
	a.state.Store(st)

	return a
}

func TestAuthorize_evaluate_MergesDecisionAndHeaders(t *testing.T) {
	t.Parallel()

	opt := &config.Options{
		AuthenticateURLString: "https://authenticate.example.com",
		Policies: []config.Policy{{
			From: "https://example.com",
			To:   mustParseWeightedURLs(t, "https://to.example.com"),
		}},
	}
	eng := &stubEngine{
		dec: &engine.Decision{
			Allow: evaluator.NewRuleResult(true, criteria.ReasonUserOK),
			Deny:  evaluator.NewRuleResult(false),
		},
	}
	a := newTestAuthorize(t, opt, eng)

	res, err := a.evaluate(t.Context(), &evaluator.Request{
		Policy: &opt.Policies[0],
		HTTP: evaluator.RequestHTTP{
			Method:  http.MethodGet,
			Headers: map[string]string{},
		},
	})
	require.NoError(t, err)
	require.NotNil(t, res)
	assert.True(t, res.Allow.Value, "decision allow should be carried through")
	assert.False(t, res.Deny.Value, "decision deny should be carried through")
	// Headers are produced by the in-process headers evaluator, which is
	// real here; we only assert the orchestrator does not drop them.
	assert.NotNil(t, res.Headers)
}

func TestAuthorize_evaluate_PrecomputesClientCertValid(t *testing.T) {
	t.Parallel()

	opt := &config.Options{
		AuthenticateURLString: "https://authenticate.example.com",
		Policies: []config.Policy{{
			From: "https://example.com",
			To:   mustParseWeightedURLs(t, "https://to.example.com"),
		}},
	}
	eng := &stubEngine{
		dec: &engine.Decision{
			Allow: evaluator.NewRuleResult(true),
			Deny:  evaluator.NewRuleResult(false),
		},
	}
	a := newTestAuthorize(t, opt, eng)

	_, err := a.evaluate(t.Context(), &evaluator.Request{
		Policy: &opt.Policies[0],
		HTTP:   evaluator.RequestHTTP{Headers: map[string]string{}},
	})
	require.NoError(t, err)
	require.NotNil(t, eng.gotReq, "engine should be invoked")
	require.NotNil(t, eng.gotReq.PrecomputedClientCertValid,
		"orchestrator must precompute client-cert validity before delegating to the engine")
}

func TestAuthorize_evaluate_EnginePreservesPrecomputedValue(t *testing.T) {
	t.Parallel()

	opt := &config.Options{
		AuthenticateURLString: "https://authenticate.example.com",
		Policies: []config.Policy{{
			From: "https://example.com",
			To:   mustParseWeightedURLs(t, "https://to.example.com"),
		}},
	}
	eng := &stubEngine{
		dec: &engine.Decision{
			Allow: evaluator.NewRuleResult(true),
			Deny:  evaluator.NewRuleResult(false),
		},
	}
	a := newTestAuthorize(t, opt, eng)

	precomputed := true
	_, err := a.evaluate(t.Context(), &evaluator.Request{
		Policy:                     &opt.Policies[0],
		HTTP:                       evaluator.RequestHTTP{Headers: map[string]string{}},
		PrecomputedClientCertValid: &precomputed,
	})
	require.NoError(t, err)
	require.NotNil(t, eng.gotReq.PrecomputedClientCertValid)
	assert.True(t, *eng.gotReq.PrecomputedClientCertValid,
		"orchestrator must not overwrite a pre-set PrecomputedClientCertValid")
}

func TestAuthorize_evaluate_PropagatesEngineError(t *testing.T) {
	t.Parallel()

	opt := &config.Options{
		AuthenticateURLString: "https://authenticate.example.com",
		Policies: []config.Policy{{
			From: "https://example.com",
			To:   mustParseWeightedURLs(t, "https://to.example.com"),
		}},
	}
	wantErr := errors.New("engine boom")
	eng := &stubEngine{err: wantErr}
	a := newTestAuthorize(t, opt, eng)

	_, err := a.evaluate(t.Context(), &evaluator.Request{
		Policy: &opt.Policies[0],
		HTTP:   evaluator.RequestHTTP{Headers: map[string]string{}},
	})
	require.Error(t, err)
	assert.ErrorIs(t, err, wantErr)
}

func TestAuthorize_evaluate_RejectsNilEngineDecision(t *testing.T) {
	t.Parallel()

	opt := &config.Options{
		AuthenticateURLString: "https://authenticate.example.com",
		Policies: []config.Policy{{
			From: "https://example.com",
			To:   mustParseWeightedURLs(t, "https://to.example.com"),
		}},
	}
	// Misbehaving engine: returns (nil, nil).
	eng := &stubEngine{}
	a := newTestAuthorize(t, opt, eng)

	_, err := a.evaluate(t.Context(), &evaluator.Request{
		Policy: &opt.Policies[0],
		HTTP:   evaluator.RequestHTTP{Headers: map[string]string{}},
	})
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrNilEngineDecision)
}

func TestPrecomputeClientCertValid(t *testing.T) {
	t.Parallel()

	t.Run("nil request is a no-op", func(t *testing.T) {
		t.Parallel()
		err := precomputeClientCertValid(nil, nil)
		assert.NoError(t, err)
	})

	t.Run("internal request is skipped", func(t *testing.T) {
		t.Parallel()
		req := &evaluator.Request{IsInternal: true}
		err := precomputeClientCertValid(nil, req)
		assert.NoError(t, err)
		assert.Nil(t, req.PrecomputedClientCertValid)
	})

	t.Run("request without policy is skipped", func(t *testing.T) {
		t.Parallel()
		req := &evaluator.Request{}
		err := precomputeClientCertValid(nil, req)
		assert.NoError(t, err)
		assert.Nil(t, req.PrecomputedClientCertValid)
	})

	t.Run("already-precomputed value is preserved", func(t *testing.T) {
		t.Parallel()
		valid := true
		req := &evaluator.Request{
			Policy:                     &config.Policy{From: "https://example.com"},
			PrecomputedClientCertValid: &valid,
		}
		err := precomputeClientCertValid(nil, req)
		assert.NoError(t, err)
		require.NotNil(t, req.PrecomputedClientCertValid)
		assert.True(t, *req.PrecomputedClientCertValid)
	})

	t.Run("populates value from evaluator", func(t *testing.T) {
		t.Parallel()
		opt := &config.Options{
			Policies: []config.Policy{{
				From: "https://example.com",
				To:   mustParseWeightedURLs(t, "https://to.example.com"),
			}},
		}
		s := store.New()
		pe, err := newPolicyEvaluator(t.Context(), opt, s, nil)
		require.NoError(t, err)

		req := &evaluator.Request{
			Policy: &opt.Policies[0],
			HTTP:   evaluator.RequestHTTP{Headers: map[string]string{}},
		}
		err = precomputeClientCertValid(pe, req)
		require.NoError(t, err)
		require.NotNil(t, req.PrecomputedClientCertValid)
	})
}
