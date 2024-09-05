// Package log provides a global logger for zerolog.
package log

import (
	"context"
	"net/http"
	"os"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	"github.com/pomerium/pomerium/internal/atomicutil"
)

// Writer is where logs are written.
var Writer *MultiWriter

var (
	zapLogger = atomicutil.NewValue(new(zap.Logger))
	zapLevel  zap.AtomicLevel
)

func init() {
	Writer = &MultiWriter{}
	Writer.Add(os.Stdout)

	zapLevel = zap.NewAtomicLevel()

	zapCfg := zap.NewProductionEncoderConfig()
	zapCfg.TimeKey = "time"
	zapCfg.EncodeTime = zapcore.RFC3339TimeEncoder

	zapLogger.Store(zap.New(zapcore.NewCore(
		zapcore.NewJSONEncoder(zapCfg),
		zapcore.Lock(os.Stdout),
		zapLevel,
	)))

	l := zerolog.New(Writer).With().Timestamp().Logger()
	log.Logger = l
	// set the default context logger
	zerolog.DefaultContextLogger = &l
	zapLevel.SetLevel(zapcore.InfoLevel)
}

// Logger returns the zerolog Logger.
func Logger() *zerolog.Logger {
	return &log.Logger
}

// ZapLogger returns the global zap logger.
func ZapLogger() *zap.Logger {
	return zapLogger.Load()
}

func GetLevel() zerolog.Level {
	return zerolog.GlobalLevel()
}

// SetLevel sets the minimum global log level.
func SetLevel(level zerolog.Level) {
	zerolog.SetGlobalLevel(level)
	switch level {
	case zerolog.DebugLevel, zerolog.TraceLevel:
		zapLevel.SetLevel(zapcore.DebugLevel)
	case zerolog.WarnLevel:
		zapLevel.SetLevel(zapcore.WarnLevel)
	case zerolog.ErrorLevel:
		zapLevel.SetLevel(zapcore.ErrorLevel)
	case zerolog.FatalLevel:
		zapLevel.SetLevel(zapcore.FatalLevel)
	case zerolog.PanicLevel:
		zapLevel.SetLevel(zapcore.PanicLevel)
	default:
		zapLevel.SetLevel(zapcore.InfoLevel)
	}
}

// With creates a child logger with the field added to its context.
func With() zerolog.Context {
	return Logger().With()
}

// Level creates a child logger with the minimum accepted level set to level.
func Level(ctx context.Context, level zerolog.Level) *zerolog.Logger {
	l := contextLogger(ctx).Level(level)
	return &l
}

// Debug starts a new message with debug level.
//
// You must call Msg on the returned event in order to send the event.
func Debug(ctx context.Context) *zerolog.Event {
	return contextLogger(ctx).Debug()
}

// Info starts a new message with info level.
//
// You must call Msg on the returned event in order to send the event.
func Info(ctx context.Context) *zerolog.Event {
	return contextLogger(ctx).Info()
}

// Warn starts a new message with warn level.
//
// You must call Msg on the returned event in order to send the event.
func Warn(ctx context.Context) *zerolog.Event {
	return contextLogger(ctx).Warn()
}

// Error starts a new message with error level.
//
// You must call Msg on the returned event in order to send the event.
func Error() *zerolog.Event {
	return log.Error()
}

func contextLogger(ctx context.Context) *zerolog.Logger {
	global := Logger()
	if global.GetLevel() == zerolog.Disabled {
		return global
	}
	l := zerolog.Ctx(ctx)
	if l.GetLevel() == zerolog.Disabled { // no logger associated with context
		return global
	}
	return l
}

// WithContext returns a context that has an associated logger and extra fields set via update
func WithContext(ctx context.Context, update func(c zerolog.Context) zerolog.Context) context.Context {
	l := contextLogger(ctx).With().Logger()
	l.UpdateContext(update)
	return l.WithContext(ctx)
}

// Fatal starts a new message with fatal level. The os.Exit(1) function
// is called by the Msg method.
//
// You must call Msg on the returned event in order to send the event.
func Fatal() *zerolog.Event {
	return Logger().Fatal()
}

// Panic starts a new message with panic level. The message is also sent
// to the panic function.
//
// You must call Msg on the returned event in order to send the event.
func Panic() *zerolog.Event {
	return Logger().Panic()
}

// Log starts a new message with no level. Setting zerolog.GlobalLevel to
// zerolog.Disabled will still disable events produced by this method.
//
// You must call Msg on the returned event in order to send the event.
func Log(_ context.Context) *zerolog.Event {
	return Logger().Log()
}

// Print sends a log event using debug level and no extra field.
// Arguments are handled in the manner of fmt.Print.
func Print(v ...any) {
	Logger().Print(v...)
}

// Printf sends a log event using debug level and no extra field.
// Arguments are handled in the manner of fmt.Printf.
func Printf(format string, v ...any) {
	Logger().Printf(format, v...)
}

// Ctx returns the Logger associated with the ctx. If no logger
// is associated, a disabled logger is returned.
func Ctx(ctx context.Context) *zerolog.Logger {
	return zerolog.Ctx(ctx)
}

// FromRequest gets the logger in the request's context.
// This is a shortcut for log.Ctx(r.Context())
func FromRequest(r *http.Request) *zerolog.Logger {
	return Ctx(r.Context())
}

// StdLogWrapper can be used to wrap logs originating from the from std
// library's ErrorFunction argument in http.Serve and httputil.ReverseProxy.
type StdLogWrapper struct {
	*zerolog.Logger
}

func (l *StdLogWrapper) Write(p []byte) (n int, err error) {
	n = len(p)
	if n > 0 && p[n-1] == '\n' {
		// Trim CR added by stdlog.
		p = p[0 : n-1]
	}
	l.Error().Msg(string(p))
	return len(p), nil
}
