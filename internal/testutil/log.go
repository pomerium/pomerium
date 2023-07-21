package testutil

import (
	"testing"

	"github.com/rs/zerolog"

	"github.com/pomerium/pomerium/internal/log"
)

// SetLogger sets the given logger as the global logger for the remainder of
// the current test. Because the logger is global, this must not be called from
// parallel tests.
func SetLogger(t *testing.T, logger *zerolog.Logger) {
	originalLogger := log.Logger()
	t.Cleanup(func() { log.SetLogger(originalLogger) })
	log.SetLogger(logger)
}
