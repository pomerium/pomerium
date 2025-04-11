package log

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/rs/zerolog"
	"google.golang.org/grpc/grpclog"
)

func init() {
	var verbosityLevel int
	if level, ok := os.LookupEnv("GRPC_GO_LOG_VERBOSITY_LEVEL"); ok {
		verbosityLevel, _ = strconv.Atoi(level) // default is 0
	}
	getLevel := GetLevel
	// if the standard grpc severity level is set, it should take priority
	if severity, ok := os.LookupEnv("GRPC_GO_LOG_SEVERITY_LEVEL"); ok {
		var severityOverride zerolog.Level
		if level, err := zerolog.ParseLevel(severity); err == nil {
			severityOverride = level
		} else {
			// some non-standard but common values
			switch strings.ToLower(strings.TrimSpace(severity)) {
			case "off":
				severityOverride = zerolog.Disabled
			case "err":
				severityOverride = zerolog.ErrorLevel
			case "warning": // zerolog only recognizes "warn"
				severityOverride = zerolog.WarnLevel
			default:
				severityOverride = zerolog.ErrorLevel
			}
		}
		getLevel = func() zerolog.Level {
			return severityOverride
		}
	}
	grpclog.SetLoggerV2(&grpcLogger{
		verbosityLevel: verbosityLevel,
		getLevel:       getLevel,
	})
}

type grpcLogger struct {
	verbosityLevel int
	getLevel       func() zerolog.Level
}

func (c *grpcLogger) Info(args ...any) {
	if c.getLevel() <= zerolog.DebugLevel {
		Logger().Debug().Msg(fmt.Sprint(args...))
	}
}

func (c *grpcLogger) Infoln(args ...any) {
	if c.getLevel() <= zerolog.DebugLevel {
		Logger().Debug().Msg(fmt.Sprintln(args...))
	}
}

func (c *grpcLogger) Infof(format string, args ...any) {
	if c.getLevel() <= zerolog.DebugLevel {
		Logger().Debug().Msg(fmt.Sprintf(format, args...))
	}
}

func (c *grpcLogger) Warning(args ...any) {
	if c.getLevel() <= zerolog.DebugLevel {
		Logger().Warn().Msg(fmt.Sprint(args...))
	}
}

func (c *grpcLogger) Warningln(args ...any) {
	if c.getLevel() <= zerolog.DebugLevel {
		Logger().Warn().Msg(fmt.Sprintln(args...))
	}
}

func (c *grpcLogger) Warningf(format string, args ...any) {
	if c.getLevel() <= zerolog.DebugLevel {
		Logger().Warn().Msg(fmt.Sprintf(format, args...))
	}
}

func (c *grpcLogger) Error(args ...any) {
	if c.getLevel() <= zerolog.DebugLevel {
		Logger().Error().Msg(fmt.Sprint(args...))
	}
}

func (c *grpcLogger) Errorln(args ...any) {
	if c.getLevel() <= zerolog.DebugLevel {
		Logger().Error().Msg(fmt.Sprintln(args...))
	}
}

func (c *grpcLogger) Errorf(format string, args ...any) {
	if c.getLevel() <= zerolog.DebugLevel {
		Logger().Error().Msg(fmt.Sprintf(format, args...))
	}
}

func (c *grpcLogger) Fatal(args ...any) {
	Logger().Fatal().Msg(fmt.Sprint(args...))
}

func (c *grpcLogger) Fatalln(args ...any) {
	Logger().Fatal().Msg(fmt.Sprintln(args...))
}

func (c *grpcLogger) Fatalf(format string, args ...any) {
	Logger().Fatal().Msg(fmt.Sprintf(format, args...))
}

func (c *grpcLogger) V(l int) bool {
	return l <= c.verbosityLevel
}
