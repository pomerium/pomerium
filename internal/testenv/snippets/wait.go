package snippets

import (
	"testing"
	"time"

	"github.com/pomerium/pomerium/internal/testenv"
)

func WaitStartupComplete(t testing.TB, env testenv.Environment, timeout ...time.Duration) time.Duration {
	start := time.Now()
	recorder := env.NewLogRecorder()
	recorder.WaitForMatch(map[string]any{
		"syncer_id":   "databroker",
		"syncer_type": "type.googleapis.com/pomerium.config.Config",
		"message":     "listening for updates",
	}, timeout...)
	return time.Since(start)
}
