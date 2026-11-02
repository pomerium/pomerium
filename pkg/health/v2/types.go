package healthv2

import (
	"context"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/pkg/health/v2/check"
)

// HealthChecker must be safe for concurrent use.
type HealthChecker interface {
	Group() check.Group
	Name() string
	// ConfigureChecks may run at the same time as Check. It returns the leaf
	// checks expected for the config; none means the checker is disabled.
	ConfigureChecks(*config.Options) []check.CheckName
	// Check must not block; it returns state the component already holds.
	Check(ctx context.Context) []check.Result
}

type HealthSink interface {
	Start()
	// Notify must not block.
	Notify(Snapshot)
	Close()
}
