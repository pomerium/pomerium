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

func (c *grpcLogger) Info(args ...interface{}) {
	if GetLevel() == zerolog.DebugLevel {
		Logger().Info().Msg(fmt.Sprint(args...))
	}
}

func (c *grpcLogger) Infoln(args ...interface{}) {
	if GetLevel() == zerolog.DebugLevel {
		Logger().Info().Msg(fmt.Sprintln(args...))
	}
}

func (c *grpcLogger) Infof(format string, args ...interface{}) {
	if GetLevel() == zerolog.DebugLevel {
		Logger().Info().Msg(fmt.Sprintf(format, args...))
	}
}

func (c *grpcLogger) Warning(args ...interface{}) {
	if GetLevel() == zerolog.DebugLevel {
		Logger().Warn().Msg(fmt.Sprint(args...))
	}
}

func (c *grpcLogger) Warningln(args ...interface{}) {
	if GetLevel() == zerolog.DebugLevel {
		Logger().Warn().Msg(fmt.Sprintln(args...))
	}
}

func (c *grpcLogger) Warningf(format string, args ...interface{}) {
	if GetLevel() == zerolog.DebugLevel {
		Logger().Warn().Msg(fmt.Sprintf(format, args...))
	}
}

func (c *grpcLogger) Error(args ...interface{}) {
	if GetLevel() == zerolog.DebugLevel {
		Logger().Error().Msg(fmt.Sprint(args...))
	}
}

func (c *grpcLogger) Errorln(args ...interface{}) {
	if GetLevel() == zerolog.DebugLevel {
		Logger().Error().Msg(fmt.Sprintln(args...))
	}
}

func (c *grpcLogger) Errorf(format string, args ...interface{}) {
	if GetLevel() == zerolog.DebugLevel {
		Logger().Error().Msg(fmt.Sprintf(format, args...))
	}
}

func (c *grpcLogger) Fatal(args ...interface{}) {
	Logger().Fatal().Msg(fmt.Sprint(args...))
}

func (c *grpcLogger) Fatalln(args ...interface{}) {
	Logger().Fatal().Msg(fmt.Sprintln(args...))
}

func (c *grpcLogger) Fatalf(format string, args ...interface{}) {
	Logger().Fatal().Msg(fmt.Sprintf(format, args...))
}

func (c *grpcLogger) V(int) bool {
	return true
}
