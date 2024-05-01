package log

import (
	"fmt"

	"google.golang.org/grpc/grpclog"
)

func init() {
	grpclog.SetLoggerV2(&grpcLogger{})
}

type grpcLogger struct{}

func (c *grpcLogger) Info(args ...interface{}) {
	Logger().Debug().Msg(fmt.Sprint(args...))
}

func (c *grpcLogger) Infoln(args ...interface{}) {
	Logger().Debug().Msg(fmt.Sprintln(args...))
}

func (c *grpcLogger) Infof(format string, args ...interface{}) {
	Logger().Debug().Msg(fmt.Sprintf(format, args...))
}

func (c *grpcLogger) Warning(args ...interface{}) {
	Logger().Debug().Msg(fmt.Sprint(args...))
}

func (c *grpcLogger) Warningln(args ...interface{}) {
	Logger().Debug().Msg(fmt.Sprintln(args...))
}

func (c *grpcLogger) Warningf(format string, args ...interface{}) {
	Logger().Debug().Msg(fmt.Sprintf(format, args...))
}

func (c *grpcLogger) Error(args ...interface{}) {
	Logger().Debug().Msg(fmt.Sprint(args...))
}

func (c *grpcLogger) Errorln(args ...interface{}) {
	Logger().Debug().Msg(fmt.Sprintln(args...))
}

func (c *grpcLogger) Errorf(format string, args ...interface{}) {
	Logger().Debug().Msg(fmt.Sprintf(format, args...))
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
