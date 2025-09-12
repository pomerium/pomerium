package health_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/pomerium/pomerium/pkg/health"
)

func TestHealthContext(t *testing.T) {
	assert := assert.New(t)
	ctx := t.Context()
	checks := health.FromContextHealthChecks(ctx)
	assert.Empty(checks)
	c1, c2, c3 := health.Check("c1"), health.Check("c2"), health.Check("c3")
	ctx = health.Context(ctx, c1)

	checks = health.FromContextHealthChecks(ctx)
	assert.ElementsMatch(checks, []health.Check{c1})

	ctx = health.Context(ctx, c2, c3)
	checks = health.FromContextHealthChecks(ctx)
	assert.ElementsMatch(checks, []health.Check{c1, c2, c3})
}
