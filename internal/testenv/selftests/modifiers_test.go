package selftests_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/testenv"
	"github.com/pomerium/pomerium/internal/testenv/snippets"
	"github.com/pomerium/pomerium/internal/testenv/values"
)

// TestStartWaitsForModifiers asserts that Start() does not return until all
// previously added modifiers have been applied.
//
// Modifiers are applied from within a task, since they can block on values that
// are only resolved once other tasks are running. Without the barrier in
// Start(), reading the configuration here would race with those writes, which
// the race detector reports as a failure.
func TestStartWaitsForModifiers(t *testing.T) {
	env := testenv.New(t)

	// resolved from within a task, so that the modifier below can only run once
	// tasks are running
	header := values.Deferred[string]()
	env.AddTask(testenv.TaskFunc(func(ctx context.Context) error {
		header.Resolve("resolved-by-task")
		<-ctx.Done()
		return nil
	}))
	env.Add(testenv.ModifierFunc(func(_ context.Context, cfg *config.Config) {
		cfg.Options.SetResponseHeaders = map[string]string{"x-modifier": header.Value()}
	}))

	env.Start()

	// asserted before waiting for startup to complete, since the guarantee under
	// test belongs to Start() itself
	assert.Equal(t, "resolved-by-task", env.Config().Options.SetResponseHeaders["x-modifier"])

	// let startup finish, so that the environment shuts down cleanly
	snippets.WaitStartupComplete(env)
}
