package log

import (
	"fmt"

	"github.com/rs/zerolog"
	"google.golang.org/grpc/grpclog"
)

func init() {
	grpclog.SetLoggerV2(&grpcLogger{})
}

type grpcLogger struct{}

func (c *grpcLogger) Info(args ...any) {
	if GetLevel() <= zerolog.DebugLevel {
		Logger().Info().Msg(fmt.Sprint(args...))
	}
}

func (c *grpcLogger) Infoln(args ...any) {
	if GetLevel() <= zerolog.DebugLevel {
		Logger().Info().Msg(fmt.Sprintln(args...))
	}
}

func (c *grpcLogger) Infof(format string, args ...any) {
	if GetLevel() <= zerolog.DebugLevel {
		Logger().Info().Msg(fmt.Sprintf(format, args...))
	}
}

func (c *grpcLogger) Warning(args ...any) {
	if GetLevel() <= zerolog.DebugLevel {
		Logger().Warn().Msg(fmt.Sprint(args...))
	}
}

func (c *grpcLogger) Warningln(args ...any) {
	if GetLevel() <= zerolog.DebugLevel {
		Logger().Warn().Msg(fmt.Sprintln(args...))
	}
}

func (c *grpcLogger) Warningf(format string, args ...any) {
	if GetLevel() <= zerolog.DebugLevel {
		Logger().Warn().Msg(fmt.Sprintf(format, args...))
	}
}

func (c *grpcLogger) Error(args ...any) {
	if GetLevel() <= zerolog.DebugLevel {
		Logger().Error().Msg(fmt.Sprint(args...))
	}
}

func (c *grpcLogger) Errorln(args ...any) {
	if GetLevel() <= zerolog.DebugLevel {
		Logger().Error().Msg(fmt.Sprintln(args...))
	}
}

func (c *grpcLogger) Errorf(format string, args ...any) {
	if GetLevel() <= zerolog.DebugLevel {
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

func (c *grpcLogger) V(int) bool {
	return true
}
