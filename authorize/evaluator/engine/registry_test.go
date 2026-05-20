package engine

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pomerium/pomerium/authorize/evaluator"
)

func TestRegister(t *testing.T) {
	defer snapshotRegistry(t)()

	t.Run("panics on empty kind", func(t *testing.T) {
		assert.PanicsWithError(t, ErrEmptyKind.Error(), func() {
			Register("", false, dummyFactory)
		})
	})

	t.Run("panics on nil factory", func(t *testing.T) {
		assert.PanicsWithError(t, ErrNilFactory.Error(), func() {
			Register("dummy-nil", false, nil)
		})
	})

	t.Run("panics on duplicate kind", func(t *testing.T) {
		Register("dup", false, dummyFactory)
		assert.PanicsWithError(
			t,
			`engine: kind already registered: "dup"`,
			func() { Register("dup", false, dummyFactory) },
		)
	})
}

func TestBuild(t *testing.T) {
	t.Run("opa default is registered", func(t *testing.T) {
		t.Parallel()
		_, err := Build("", FactoryConfig{OPAInner: nil})
		// OPA requires an inner; the registry call still succeeds.
		assert.ErrorIs(t, err, ErrNilEvaluator)
	})

	t.Run("unknown kind", func(t *testing.T) {
		t.Parallel()
		_, err := Build("bogus", FactoryConfig{})
		assert.ErrorIs(t, err, ErrUnknownKind)
	})

	t.Run("external requires flag", func(t *testing.T) {
		defer snapshotRegistry(t)()
		Register("test-ext", true, func(_ FactoryConfig) (PolicyEngine, error) {
			return &noopEngine{}, nil
		})

		_, err := Build("test-ext", FactoryConfig{})
		assert.ErrorIs(t, err, ErrExternalNotAllowed)

		e, err := Build("test-ext", FactoryConfig{ExternalEnginesEnabled: true})
		require.NoError(t, err)
		assert.NotNil(t, e)
	})
}

func TestRegisteredKinds(t *testing.T) {
	// Not parallel: the registry is global state mutated by other tests in
	// this file via snapshotRegistry.
	kinds := RegisteredKinds()
	assert.Contains(t, kinds, KindOPA)
	for i := 1; i < len(kinds); i++ {
		assert.LessOrEqual(t, string(kinds[i-1]), string(kinds[i]), "kinds must be sorted")
	}
}

// snapshotRegistry captures the current registry state and returns a
// restore function. It is intended for tests that register additional
// factories and need to leave the global registry clean afterwards.
func snapshotRegistry(t *testing.T) func() {
	t.Helper()
	registry.mu.Lock()
	defer registry.mu.Unlock()

	savedFactories := make(map[Kind]Factory, len(registry.factories))
	savedExternal := make(map[Kind]bool, len(registry.external))
	for k, v := range registry.factories {
		savedFactories[k] = v
	}
	for k, v := range registry.external {
		savedExternal[k] = v
	}

	return func() {
		registry.mu.Lock()
		defer registry.mu.Unlock()
		registry.factories = savedFactories
		registry.external = savedExternal
	}
}

// dummyFactory is the no-op factory used by registry tests.
func dummyFactory(_ FactoryConfig) (PolicyEngine, error) { return &noopEngine{}, nil }

// noopEngine is a minimal PolicyEngine for use in registry tests.
type noopEngine struct{}

func (noopEngine) Evaluate(_ context.Context, _ *evaluator.Request) (*Decision, error) {
	return &Decision{Allow: evaluator.NewRuleResult(true)}, nil
}
func (noopEngine) Close() error { return nil }
