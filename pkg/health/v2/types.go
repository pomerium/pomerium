package healthv2

import (
	"context"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/pkg/health/v2/check"
)

// HealthChecker must be safe for concurrent use: ConfigureChecks may run at the
// same time as Check. ConfigureChecks returns the leaf checks expected for the
// config; none means the checker is disabled. Leaf names are unique across
// checkers. Check must not block; it returns state the component already holds.
type HealthChecker interface {
	Group() check.Group
	Name() string
	ConfigureChecks(*config.Options) []check.CheckName
	Check(ctx context.Context) []check.Result
}

// HealthSink is notified with the latest snapshot after each poll whose
// snapshot differs. Notify must not block the manager.
type HealthSink interface {
	Notify(Snapshot)
	Close()
}
