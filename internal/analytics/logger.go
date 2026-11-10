package analytics

import "github.com/pomerium/pomerium/internal/log"

type posthogLogger struct{}

func (posthogLogger) Debugf(format string, args ...any) {
	log.Debug().Msgf(format, args...)
}

func (posthogLogger) Logf(format string, args ...any) {
	log.Info().Msgf(format, args...)
}

func (posthogLogger) Warnf(format string, args ...any) {
	log.Error().Msgf(format, args...)
}

func (posthogLogger) Errorf(format string, args ...any) {
	log.Error().Msgf(format, args...)
}
