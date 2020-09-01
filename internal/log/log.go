// Package log provides a global logger for zerolog.
package log

import (
	"context"
	"net/http"
	"os"
	"sync/atomic"

	"github.com/rs/zerolog"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

var (
	logger    atomic.Value
	zapLogger atomic.Value
	zapLevel  zap.AtomicLevel
)

func init() {
	zapLevel = zap.NewAtomicLevel()

	zapCfg := zap.NewProductionEncoderConfig()
	zapCfg.TimeKey = "time"
	zapCfg.EncodeTime = zapcore.RFC3339TimeEncoder

	zapLogger.Store(zap.New(zapcore.NewCore(
		zapcore.NewJSONEncoder(zapCfg),
		zapcore.Lock(os.Stdout),
		zapLevel,
	)))

	DisableDebug()
}

// DisableDebug tells the logger to use stdout and json output.
func DisableDebug() {
	l := zerolog.New(os.Stdout).With().Timestamp().Logger()
	logger.Store(&l)
	zapLevel.SetLevel(zapcore.InfoLevel)
}

// EnableDebug tells the logger to use stdout and pretty print output.
func EnableDebug() {
	l := zerolog.New(os.Stdout).With().Timestamp().Logger().Output(zerolog.ConsoleWriter{Out: os.Stdout})
	logger.Store(&l)
	zapLevel.SetLevel(zapcore.DebugLevel)
}

// Logger returns the global logger.
func Logger() *zerolog.Logger {
	return logger.Load().(*zerolog.Logger)
}

// ZapLogger returns the global zap logger.
func ZapLogger() *zap.Logger {
	return zapLogger.Load().(*zap.Logger)
}

// SetLevel sets the minimum global log level. Options are 'debug' 'info' 'warn' and 'error'.
// Defaults to 'debug'
func SetLevel(level string) {
	switch level {
	case "info":
		zerolog.SetGlobalLevel(zerolog.InfoLevel)
	case "warn":
		zerolog.SetGlobalLevel(zerolog.WarnLevel)
	case "error":
		zerolog.SetGlobalLevel(zerolog.ErrorLevel)
	default:
		zerolog.SetGlobalLevel(zerolog.DebugLevel)
	}
}

// With creates a child logger with the field added to its context.
func With() zerolog.Context {
	return Logger().With()
}

// Level creates a child logger with the minimum accepted level set to level.
func Level(level zerolog.Level) zerolog.Logger {
	return Logger().Level(level)
}

// Debug starts a new message with debug level.
//
// You must call Msg on the returned event in order to send the event.
func Debug() *zerolog.Event {
	return Logger().Debug()
}

// Info starts a new message with info level.
//
// You must call Msg on the returned event in order to send the event.
func Info() *zerolog.Event {
	return Logger().Info()
}

// Warn starts a new message with warn level.
//
// You must call Msg on the returned event in order to send the event.
func Warn() *zerolog.Event {
	return Logger().Warn()
}

// Error starts a new message with error level.
//
// You must call Msg on the returned event in order to send the event.
func Error() *zerolog.Event {
	return Logger().Error()
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

// WithLevel starts a new message with level.
//
// You must call Msg on the returned event in order to send the event.
func WithLevel(level zerolog.Level) *zerolog.Event {
	return Logger().WithLevel(level)
}

// Log starts a new message with no level. Setting zerolog.GlobalLevel to
// zerolog.Disabled will still disable events produced by this method.
//
// You must call Msg on the returned event in order to send the event.
func Log() *zerolog.Event {
	return Logger().Log()
}

// Print sends a log event using debug level and no extra field.
// Arguments are handled in the manner of fmt.Print.
func Print(v ...interface{}) {
	Logger().Print(v...)
}

// Printf sends a log event using debug level and no extra field.
// Arguments are handled in the manner of fmt.Printf.
func Printf(format string, v ...interface{}) {
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
