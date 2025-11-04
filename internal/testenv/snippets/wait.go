package snippets

import (
	"time"

	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/internal/testenv"
	"github.com/pomerium/pomerium/pkg/telemetry/trace"
)

func WaitStartupComplete(env testenv.Environment, timeout ...time.Duration) time.Duration {
	if env.GetState() == testenv.NotRunning {
		panic("test bug: WaitStartupComplete called before starting the test environment")
	}
	_, span := trace.Continue(env.Context(), "snippets.WaitStartupComplete")
	defer span.End()
	start := time.Now()
	recorder := env.NewLogRecorder()
	if len(timeout) == 0 {
		timeout = append(timeout, 1*time.Minute)
	}
	log.Ctx(env.Context()).Warn().Msg(">>> waiting for startup to complete...")
	recorder.WaitForMatch(map[string]any{
		"syncer-id":   "databroker",
		"syncer-type": "type.googleapis.com/pomerium.config.Config",
		"message":     "listening for updates",
	}, timeout...)
	return time.Since(start)
}
