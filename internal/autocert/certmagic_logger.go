package autocert

import (
	"strings"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	"github.com/pomerium/pomerium/internal/log"
)

type certMagicLoggerCore struct {
	core   zapcore.Core
	fields []zapcore.Field
}

func (c certMagicLoggerCore) Enabled(lvl zapcore.Level) bool {
	return c.core.Enabled(lvl)
}

func (c certMagicLoggerCore) With(fs []zapcore.Field) zapcore.Core {
	return certMagicLoggerCore{core: c.core, fields: append(c.fields, fs...)}
}

func (c certMagicLoggerCore) Check(e zapcore.Entry, ce *zapcore.CheckedEntry) *zapcore.CheckedEntry {
	return ce.AddCore(e, c)
}

func (c certMagicLoggerCore) Write(e zapcore.Entry, fs []zapcore.Field) error {
	fs = append(c.fields, fs...)
	for _, f := range fs {
		if f.Type == zapcore.ErrorType && strings.Contains(f.Interface.(error).Error(), "no OCSP server specified in certificate") {
			// ignore this error message (#4245)
			return nil
		}
	}
	return c.core.Write(e, fs)
}

func (c certMagicLoggerCore) Sync() error {
	return c.core.Sync()
}

func getCertMagicLogger() *zap.Logger {
	logger := log.ZapLogger().With(zap.String("service", "autocert"))
	logger = logger.WithOptions(zap.WrapCore(func(c zapcore.Core) zapcore.Core {
		return certMagicLoggerCore{core: c}
	}))
	return logger
}
