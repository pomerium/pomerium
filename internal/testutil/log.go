package testutil

import (
	"testing"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

// SetLogger sets the given logger as the global logger for the remainder of
// the current test. Because the logger is global, this must not be called from
// parallel tests.
func SetLogger(t *testing.T, logger zerolog.Logger) {
	t.Helper()

	originalLogger := log.Logger
	t.Cleanup(func() { log.Logger = originalLogger })
	log.Logger = logger

	originalContextLogger := zerolog.DefaultContextLogger
	t.Cleanup(func() { zerolog.DefaultContextLogger = originalContextLogger })
	zerolog.DefaultContextLogger = &logger
}
