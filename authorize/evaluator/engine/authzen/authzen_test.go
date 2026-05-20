package authzen

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pomerium/pomerium/authorize/evaluator"
	"github.com/pomerium/pomerium/authorize/evaluator/engine"
	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/pkg/policy/criteria"
)

func TestNew(t *testing.T) {
	t.Parallel()

	t.Run("missing endpoint", func(t *testing.T) {
		t.Parallel()
		_, err := New(Config{})
		assert.ErrorIs(t, err, ErrMissingEndpoint)
	})

	t.Run("applies defaults", func(t *testing.T) {
		t.Parallel()
		e, err := New(Config{Endpoint: "https://pdp.example.com"})
		require.NoError(t, err)
		assert.Equal(t, "https://pdp.example.com"+DefaultEvaluatePath, e.url)
		assert.Equal(t, DefaultTimeout, e.cfg.Timeout)
		assert.Equal(t, DefaultSubjectType, e.cfg.SubjectType)
		assert.Equal(t, DefaultResourceType, e.cfg.ResourceType)
	})

	t.Run("preserves explicit values", func(t *testing.T) {
		t.Parallel()
		e, err := New(Config{
			Endpoint:     "https://pdp.example.com/",
			EvaluatePath: "/v2/eval",
			SubjectType:  "person",
			ResourceType: "route",
			Timeout:      7 * time.Second,
		})
		require.NoError(t, err)
		assert.Equal(t, "https://pdp.example.com/v2/eval", e.url)
		assert.Equal(t, 7*time.Second, e.cfg.Timeout)
	})
}

func TestEngine_Evaluate_PreChecks(t *testing.T) {
	t.Parallel()

	e := mustNewWithServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		t.Errorf("PDP must not be called in pre-check scenarios")
		w.WriteHeader(http.StatusInternalServerError)
	}))

	privatePolicy := &config.Policy{}

	cases := []struct {
		name        string
		req         *evaluator.Request
		wantAllow   bool
		wantDeny    bool
		wantReasons []criteria.Reason
	}{
		{
			name:        "nil request",
			req:         nil,
			wantDeny:    true,
			wantReasons: []criteria.Reason{criteria.ReasonRouteNotFound},
		},
		{
			name:        "nil policy",
			req:         &evaluator.Request{},
			wantDeny:    true,
			wantReasons: []criteria.Reason{criteria.ReasonRouteNotFound},
		},
		{
			name:        "internal route",
			req:         &evaluator.Request{IsInternal: true, Policy: privatePolicy},
			wantAllow:   true,
			wantReasons: []criteria.Reason{criteria.ReasonPomeriumRoute},
		},
		{
			name:        "missing session on private route",
			req:         &evaluator.Request{Policy: privatePolicy},
			wantDeny:    true,
			wantReasons: []criteria.Reason{criteria.ReasonUserUnauthenticated},
		},
	}

	for i := range cases {
		c := &cases[i]
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			dec, err := e.Evaluate(t.Context(), c.req)
			require.NoError(t, err)
			require.NotNil(t, dec)
			assert.Equal(t, c.wantAllow, dec.Allow.Value)
			assert.Equal(t, c.wantDeny, dec.Deny.Value)
			for _, r := range c.wantReasons {
				assert.True(t, dec.Allow.Reasons.Has(r) || dec.Deny.Reasons.Has(r),
					"expected reason %q", r)
			}
		})
	}
}

func TestEngine_Evaluate_DelegatesToPDP(t *testing.T) {
	t.Parallel()

	policy := newPolicy(t)

	t.Run("allow decision", func(t *testing.T) {
		t.Parallel()
		var got evaluationRequest
		e := mustNewWithServer(t, requestCapturingHandler(t, &got, true))

		dec, err := e.Evaluate(t.Context(), &evaluator.Request{
			Policy:  policy,
			HTTP:    evaluator.RequestHTTP{Method: http.MethodGet, Host: "from.example.com", Path: "/"},
			Session: evaluator.RequestSession{ID: "s1", UserID: "u1"},
		})
		require.NoError(t, err)
		assert.True(t, dec.Allow.Value)
		assert.True(t, dec.Allow.Reasons.Has(criteria.ReasonUserOK))

		assert.Equal(t, "u1", got.Subject.ID)
		assert.Equal(t, DefaultSubjectType, got.Subject.Type)
		assert.Equal(t, "can_read", got.Action.Name)
		assert.Equal(t, http.MethodGet, got.Action.Properties["method"])
		assert.Equal(t, DefaultResourceType, got.Resource.Type)
		assert.NotEmpty(t, got.Resource.ID)
	})

	t.Run("deny decision", func(t *testing.T) {
		t.Parallel()
		var got evaluationRequest
		e := mustNewWithServer(t, requestCapturingHandler(t, &got, false))

		dec, err := e.Evaluate(t.Context(), &evaluator.Request{
			Policy:  policy,
			HTTP:    evaluator.RequestHTTP{Method: http.MethodGet, Host: "from.example.com"},
			Session: evaluator.RequestSession{ID: "s1", UserID: "u1"},
		})
		require.NoError(t, err)
		assert.False(t, dec.Allow.Value)
		assert.True(t, dec.Deny.Value)
		assert.True(t, dec.Deny.Reasons.Has(criteria.ReasonUserUnauthorized))
	})

	t.Run("forwards Authorization header", func(t *testing.T) {
		t.Parallel()
		var seen atomic.Value
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			seen.Store(r.Header.Get("Authorization"))
			w.Header().Set("Content-Type", contentTypeJSON)
			_, _ = w.Write([]byte(`{"decision":true}`))
		}))
		t.Cleanup(srv.Close)

		e, err := New(Config{Endpoint: srv.URL, AuthHeader: "Bearer abc"})
		require.NoError(t, err)

		_, err = e.Evaluate(t.Context(), &evaluator.Request{
			Policy:  newPolicy(t),
			HTTP:    evaluator.RequestHTTP{Method: http.MethodGet, Host: "from.example.com"},
			Session: evaluator.RequestSession{ID: "s1", UserID: "u1"},
		})
		require.NoError(t, err)
		assert.Equal(t, "Bearer abc", seen.Load())
	})
}

func TestEngine_Evaluate_PDPErrors(t *testing.T) {
	t.Parallel()

	policy := newPolicy(t)
	req := &evaluator.Request{
		Policy:  policy,
		HTTP:    evaluator.RequestHTTP{Method: http.MethodGet, Host: "from.example.com"},
		Session: evaluator.RequestSession{ID: "s1", UserID: "u1"},
	}

	cases := []struct {
		name    string
		handler http.HandlerFunc
		wantErr error
	}{
		{
			name: "non-200 status",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusServiceUnavailable)
				_, _ = w.Write([]byte("pdp overloaded"))
			},
			wantErr: ErrPDPResponse,
		},
		{
			name: "wrong content-type",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "text/plain")
				_, _ = w.Write([]byte(`{"decision":true}`))
			},
			wantErr: ErrPDPResponse,
		},
		{
			name: "invalid json",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", contentTypeJSON)
				_, _ = w.Write([]byte(`not json`))
			},
			wantErr: ErrPDPResponse,
		},
	}

	for i := range cases {
		c := &cases[i]
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			e := mustNewWithServer(t, c.handler)
			_, err := e.Evaluate(t.Context(), req)
			assert.ErrorIs(t, err, c.wantErr)
		})
	}
}

func TestFactoryRegistration(t *testing.T) {
	t.Parallel()
	assert.Contains(t, engine.RegisteredKinds(), KindAuthZEN)

	t.Run("flag required", func(t *testing.T) {
		t.Parallel()
		_, err := engine.Build(KindAuthZEN, engine.FactoryConfig{})
		assert.ErrorIs(t, err, engine.ErrExternalNotAllowed)
	})

	t.Run("builds with map config", func(t *testing.T) {
		t.Parallel()
		e, err := engine.Build(KindAuthZEN, engine.FactoryConfig{
			ExternalEnginesEnabled: true,
			EngineConfig: map[string]any{
				"endpoint": "https://pdp.example.com",
			},
		})
		require.NoError(t, err)
		assert.NotNil(t, e)
		assert.NoError(t, e.Close())
	})

	t.Run("rejects unsupported config type", func(t *testing.T) {
		t.Parallel()
		_, err := engine.Build(KindAuthZEN, engine.FactoryConfig{
			ExternalEnginesEnabled: true,
			EngineConfig:           42,
		})
		assert.ErrorIs(t, err, ErrInvalidConfig)
	})
}

func TestCanonicalAction(t *testing.T) {
	t.Parallel()
	cases := map[string]string{
		http.MethodGet:     "can_read",
		http.MethodHead:    "can_read",
		http.MethodOptions: "can_read",
		http.MethodPost:    "can_create",
		http.MethodPut:     "can_update",
		http.MethodPatch:   "can_update",
		http.MethodDelete:  "can_delete",
		"WEIRDVERB":        "can_access",
		"":                 "can_access",
	}
	for method, want := range cases {
		t.Run(method+"->"+want, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, want, canonicalAction(method))
		})
	}
}

// mustNewWithServer constructs an Engine pointed at a httptest server
// running the given handler.
func mustNewWithServer(t *testing.T, h http.Handler) *Engine {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	e, err := New(Config{Endpoint: srv.URL})
	require.NoError(t, err)
	return e
}

// requestCapturingHandler decodes the incoming evaluation request into
// got and replies with the given decision.
func requestCapturingHandler(t *testing.T, got *evaluationRequest, decision bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, http.MethodPost, r.Method)
		require.True(t, strings.HasSuffix(r.URL.Path, DefaultEvaluatePath))
		body, err := io.ReadAll(r.Body)
		require.NoError(t, err)
		require.NoError(t, json.Unmarshal(body, got))

		w.Header().Set("Content-Type", contentTypeJSON)
		_ = json.NewEncoder(w).Encode(evaluationResponse{Decision: decision})
	}
}

// newPolicy returns a config.Policy whose RouteID() succeeds.
func newPolicy(t *testing.T) *config.Policy {
	t.Helper()
	to, err := config.ParseWeightedUrls("https://to.example.com")
	require.NoError(t, err)
	p := &config.Policy{From: "https://from.example.com", To: to}
	_, err = p.RouteID()
	require.NoError(t, err)
	return p
}
