package evaluator

import (
	"testing"
	"time"

	"github.com/open-policy-agent/opa/rego"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pomerium/pomerium/authorize/internal/store"
	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/pkg/secrets/resolver"
)

// fakeView returns scripted lookup results and counts lookups.
type fakeView struct {
	results map[string]resolver.LookupResult
	lookups int
}

func (v *fakeView) Lookup(id string) resolver.LookupResult {
	v.lookups++
	return v.results[id]
}

// fakeSecretsLookup hands out a (possibly changing) view and counts View calls.
type fakeSecretsLookup struct {
	views     []*fakeView
	viewCalls int
}

func (f *fakeSecretsLookup) View() resolver.View {
	v := f.views[min(f.viewCalls, len(f.views)-1)]
	f.viewCalls++
	return v
}

func fresh(v string) resolver.LookupResult {
	return resolver.LookupResult{Value: v, State: resolver.StateFresh, Found: true}
}

func evalSecretHeaders(t *testing.T, lookup store.SecretsLookup, headers map[string]string) *HeadersResponse {
	t.Helper()
	s := store.New()
	if lookup != nil {
		s.UpdateSecretsLookup(lookup)
	}
	e := NewHeadersEvaluator(s)
	res, err := e.Evaluate(t.Context(), &Request{
		HTTP:    RequestHTTP{Hostname: "from.example.com"},
		Policy:  &config.Policy{From: "https://from.example.com", SetRequestHeaders: headers},
		Session: RequestSession{ID: "s1"},
	}, rego.EvalTime(time.Unix(1686870680, 0)))
	require.NoError(t, err)
	return res
}

func TestFillSetRequestHeadersSecrets(t *testing.T) {
	t.Parallel()

	t.Run("fresh value injected", func(t *testing.T) {
		t.Parallel()
		lookup := &fakeSecretsLookup{views: []*fakeView{{results: map[string]resolver.LookupResult{
			"tok": fresh("s3cr3t"),
		}}}}
		res := evalSecretHeaders(t, lookup, map[string]string{"Authorization": "Bearer ${secret.tok}"})
		assert.Equal(t, "Bearer s3cr3t", res.Headers.Get("Authorization"))
		assert.Nil(t, res.SecretsUnavailable)
	})

	t.Run("repeated ref in one value", func(t *testing.T) {
		t.Parallel()
		lookup := &fakeSecretsLookup{views: []*fakeView{{results: map[string]resolver.LookupResult{
			"tok": fresh("XYZ"),
		}}}}
		res := evalSecretHeaders(t, lookup, map[string]string{"X": "${secret.tok}-${secret.tok}"})
		assert.Equal(t, "XYZ-XYZ", res.Headers.Get("X"))
	})

	t.Run("stale value still injected", func(t *testing.T) {
		t.Parallel()
		lookup := &fakeSecretsLookup{views: []*fakeView{{results: map[string]resolver.LookupResult{
			"tok": {Value: "stale-val", State: resolver.StateStale, Found: true},
		}}}}
		res := evalSecretHeaders(t, lookup, map[string]string{"X": "${secret.tok}"})
		assert.Equal(t, "stale-val", res.Headers.Get("X"))
		assert.Nil(t, res.SecretsUnavailable)
	})

	t.Run("unavailable rejects with marker and no partial header", func(t *testing.T) {
		t.Parallel()
		lookup := &fakeSecretsLookup{views: []*fakeView{{results: map[string]resolver.LookupResult{
			"tok": {State: resolver.StateExpired, Found: true},
		}}}}
		res := evalSecretHeaders(t, lookup, map[string]string{"Authorization": "Bearer ${secret.tok}"})
		require.NotNil(t, res.SecretsUnavailable)
		assert.Equal(t, "tok", res.SecretsUnavailable.BindingID)
		assert.Equal(t, "Authorization", res.SecretsUnavailable.HeaderName)
		assert.Empty(t, res.Headers.Get("Authorization"), "no partially-built header")
	})

	t.Run("failed state rejects", func(t *testing.T) {
		t.Parallel()
		lookup := &fakeSecretsLookup{views: []*fakeView{{results: map[string]resolver.LookupResult{
			"tok": {State: resolver.StateFailed, Found: true},
		}}}}
		res := evalSecretHeaders(t, lookup, map[string]string{"X": "${secret.tok}"})
		require.NotNil(t, res.SecretsUnavailable)
	})

	t.Run("unknown id rejects (config race)", func(t *testing.T) {
		t.Parallel()
		lookup := &fakeSecretsLookup{views: []*fakeView{{results: map[string]resolver.LookupResult{}}}}
		res := evalSecretHeaders(t, lookup, map[string]string{"X": "${secret.gone}"})
		require.NotNil(t, res.SecretsUnavailable)
		assert.Equal(t, "gone", res.SecretsUnavailable.BindingID)
	})

	t.Run("nil lookup fails closed", func(t *testing.T) {
		t.Parallel()
		res := evalSecretHeaders(t, nil, map[string]string{"X": "${secret.tok}"})
		require.NotNil(t, res.SecretsUnavailable)
		assert.Empty(t, res.Headers.Get("X"))
	})

	t.Run("value with newline fails closed", func(t *testing.T) {
		t.Parallel()
		lookup := &fakeSecretsLookup{views: []*fakeView{{results: map[string]resolver.LookupResult{
			"tok": fresh("bad\nvalue"),
		}}}}
		res := evalSecretHeaders(t, lookup, map[string]string{"X": "${secret.tok}"})
		require.NotNil(t, res.SecretsUnavailable)
		assert.Empty(t, res.Headers.Get("X"))
	})

	t.Run("deterministic smallest header name on multiple failures", func(t *testing.T) {
		t.Parallel()
		for range 20 {
			lookup := &fakeSecretsLookup{views: []*fakeView{{results: map[string]resolver.LookupResult{
				"tok": {State: resolver.StateExpired, Found: true},
			}}}}
			res := evalSecretHeaders(t, lookup, map[string]string{
				"Z-Header": "${secret.tok}",
				"A-Header": "${secret.tok}",
				"M-Header": "${secret.tok}",
			})
			require.NotNil(t, res.SecretsUnavailable)
			assert.Equal(t, "A-Header", res.SecretsUnavailable.HeaderName)
		}
	})

	t.Run("no secret refs never touches lookup", func(t *testing.T) {
		t.Parallel()
		lookup := &fakeSecretsLookup{views: []*fakeView{{results: map[string]resolver.LookupResult{}}}}
		res := evalSecretHeaders(t, lookup, map[string]string{"X": "static-value"})
		assert.Equal(t, "static-value", res.Headers.Get("X"))
		assert.Zero(t, lookup.viewCalls, "hot-path guard: no secret refs => no View()")
	})

	t.Run("one view per evaluation", func(t *testing.T) {
		t.Parallel()
		// Two different views; if the fill loop captured more than one, the two
		// headers would disagree.
		lookup := &fakeSecretsLookup{views: []*fakeView{
			{results: map[string]resolver.LookupResult{"tok": fresh("first")}},
			{results: map[string]resolver.LookupResult{"tok": fresh("second")}},
		}}
		res := evalSecretHeaders(t, lookup, map[string]string{
			"A": "${secret.tok}",
			"B": "${secret.tok}",
		})
		assert.Equal(t, "first", res.Headers.Get("A"))
		assert.Equal(t, "first", res.Headers.Get("B"))
		assert.Equal(t, 1, lookup.viewCalls, "View captured exactly once per evaluation")
	})
}
