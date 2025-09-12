package health

import (
	"context"

	"github.com/pomerium/pomerium/pkg/slices"
)

type healthContextKeyType struct{}

var healthContextKey healthContextKeyType

type healthContext struct {
	expectedChecks []Check
}

// HealthContext injects additional checks from out-of-band integrations
// like ingress-controller
func Context(ctx context.Context, additionalChecks ...Check) context.Context {
	health, ok := ctx.Value(healthContextKey).(*healthContext)
	if !ok {
		return context.WithValue(ctx, healthContextKey, &healthContext{
			expectedChecks: additionalChecks,
		})
	}
	health.expectedChecks = slices.Unique(append(health.expectedChecks, additionalChecks...))
	return ctx
}

func FromContextHealthChecks(ctx context.Context) []Check {
	health, ok := ctx.Value(healthContextKey).(*healthContext)
	if !ok {
		return []Check{}
	}
	return health.expectedChecks
}
