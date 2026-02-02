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
	logLevel := zerolog.Disabled
	if severity, ok := os.LookupEnv("GRPC_GO_LOG_SEVERITY_LEVEL"); ok {
		if level, err := zerolog.ParseLevel(severity); err == nil {
			logLevel = level
		} else {
			// some non-standard but common values
			switch strings.ToLower(strings.TrimSpace(severity)) {
			case "off":
				logLevel = zerolog.Disabled
			case "err":
				logLevel = zerolog.ErrorLevel
			case "warning": // zerolog only recognizes "warn"
				logLevel = zerolog.WarnLevel
			default:
				logLevel = zerolog.ErrorLevel
			}
		}
	}
	grpclog.SetLoggerV2(&grpcLogger{
		verbosityLevel: verbosityLevel,
		logLevel:       logLevel,
	})
}

type grpcLogger struct {
	verbosityLevel int
	logLevel       zerolog.Level
}

func (c *grpcLogger) Info(args ...any) {
	Logger().Debug().Msg(fmt.Sprint(args...))
}

func (c *grpcLogger) Infoln(args ...any) {
	Logger().Debug().Msg(fmt.Sprintln(args...))
}

func (c *grpcLogger) Infof(format string, args ...any) {
	Logger().Debug().Msg(fmt.Sprintf(format, args...))
}

func (c *grpcLogger) Warning(args ...any) {
	Logger().Warn().Msg(fmt.Sprint(args...))
}

func (c *grpcLogger) Warningln(args ...any) {
	Logger().Warn().Msg(fmt.Sprintln(args...))
}

func (c *grpcLogger) Warningf(format string, args ...any) {
	Logger().Warn().Msg(fmt.Sprintf(format, args...))
}

func (c *grpcLogger) Error(args ...any) {
	Logger().Error().Msg(fmt.Sprint(args...))
}

func (c *grpcLogger) Errorln(args ...any) {
	Logger().Error().Msg(fmt.Sprintln(args...))
}

func (c *grpcLogger) Errorf(format string, args ...any) {
	Logger().Error().Msg(fmt.Sprintf(format, args...))
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
