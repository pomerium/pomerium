package config

import (
	"fmt"

	"github.com/rs/zerolog"
)

// A LogLevel represents a logging level.
type LogLevel string

// Known log levels.
const (
	LogLevelUnset    LogLevel = "" // defaults to info
	LogLevelTrace    LogLevel = "trace"
	LogLevelDebug    LogLevel = "debug"
	LogLevelInfo     LogLevel = "info"
	LogLevelWarn     LogLevel = "warn"
	LogLevelWarning  LogLevel = "warning"
	LogLevelError    LogLevel = "error"
	LogLevelCritical LogLevel = "critical"
	LogLevelFatal    LogLevel = "fatal"
	LogLevelPanic    LogLevel = "panic"
	LogLevelOff      LogLevel = "off"
	LogLevelNone     LogLevel = "none"
	LogLevelDisabled LogLevel = "disabled"
)

// AllLogLevels are all of the known log levels.
var AllLogLevels = [...]LogLevel{
	LogLevelUnset,
	LogLevelTrace,
	LogLevelDebug,
	LogLevelInfo,
	LogLevelWarn,
	LogLevelWarning,
	LogLevelError,
	LogLevelCritical,
	LogLevelFatal,
	LogLevelPanic,
	LogLevelOff,
	LogLevelNone,
	LogLevelDisabled,
}

var logLevelLookup = func() map[LogLevel]struct{} {
	m := map[LogLevel]struct{}{}
	for _, lvl := range AllLogLevels {
		m[lvl] = struct{}{}
	}
	return m
}()

// ValidateLogLevel validates that a log level is one of the known log levels.
func ValidateLogLevel(lvl LogLevel) error {
	_, ok := logLevelLookup[lvl]
	if !ok {
		return fmt.Errorf("unknown log level: %s", lvl)
	}
	return nil
}

// ToZerolog converts the log level to a level zerolog expects
func (lvl LogLevel) ToZerolog() zerolog.Level {
	switch lvl {
	case LogLevelTrace:
		return zerolog.TraceLevel
	case LogLevelDebug:
		return zerolog.DebugLevel
	case LogLevelInfo, LogLevelUnset:
		return zerolog.InfoLevel
	case LogLevelWarn, LogLevelWarning:
		return zerolog.WarnLevel
	case LogLevelError:
		return zerolog.ErrorLevel
	case LogLevelCritical, LogLevelFatal:
		return zerolog.FatalLevel
	case LogLevelPanic:
		return zerolog.PanicLevel
	case LogLevelOff, LogLevelNone, LogLevelDisabled:
		return zerolog.Disabled
	default:
		panic(fmt.Sprintf("unknown log level: %s", lvl))
	}
}

// ToEnvoy converts the log level to a string envoy expects.
func (lvl LogLevel) ToEnvoy() string {
	switch lvl {
	case LogLevelTrace:
		return "trace"
	case LogLevelDebug:
		return "debug"
	case LogLevelInfo, LogLevelUnset:
		return "info"
	case LogLevelWarn, LogLevelWarning:
		return "warn"
	case LogLevelError:
		return "error"
	case LogLevelCritical, LogLevelFatal, LogLevelPanic:
		return "critical"
	case LogLevelOff, LogLevelNone, LogLevelDisabled:
		return "off"
	default:
		panic(fmt.Sprintf("unknown log level: %s", lvl))
	}
}
