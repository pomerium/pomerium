// Package log provides a global logger for zerolog.
package log

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"os"
	"sync/atomic"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// Writer is where logs are written.
var Writer *MultiWriter

// ConsoleLogBuffer is the ring buffer for on-demand log streaming to Zero Console.
// It is only added to the Writer when LogToConsole is enabled.
var ConsoleLogBuffer = NewRingBuffer()

var (
	consoleLogEnabled atomic.Bool

	zapLogger atomic.Pointer[zap.Logger]
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

// EnableConsoleLog adds the ring buffer to the MultiWriter.
// It is idempotent — calling it multiple times has no effect.
func EnableConsoleLog() {
	if consoleLogEnabled.CompareAndSwap(false, true) {
		Writer.Add(ConsoleLogBuffer)
	}
}

// DisableConsoleLog removes the ring buffer from the MultiWriter.
func DisableConsoleLog() {
	if consoleLogEnabled.CompareAndSwap(true, false) {
		Writer.Remove(ConsoleLogBuffer)
	}
}

// Logger returns the zerolog Logger.
func Logger() *zerolog.Logger {
	return &log.Logger
}

// ZapLogger returns the global zap logger.
func ZapLogger() *zap.Logger {
	if DebugDisableZapLogger.Load() {
		return zap.NewNop()
	}
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

// Debug starts a new message with debug level.
//
// You must call Msg on the returned event in order to send the event.
func Debug() *zerolog.Event {
	return log.Debug()
}

// Info starts a new message with info level.
//
// You must call Msg on the returned event in order to send the event.
func Info() *zerolog.Event {
	return log.Info()
}

// Error starts a new message with error level.
//
// You must call Msg on the returned event in order to send the event.
func Error() *zerolog.Event {
	return log.Error()
}

// WithContext returns a context that has an associated logger and extra fields set via update
func WithContext(ctx context.Context, update func(c zerolog.Context) zerolog.Context) context.Context {
	l := log.Ctx(ctx).With().Logger()
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

// CaptureOutput captures log output by attaching a new logger to the context.
func CaptureOutput(ctx context.Context, fn func(context.Context)) string {
	var buf1, buf2 bytes.Buffer
	l := zerolog.New(&buf1)
	fn(l.WithContext(ctx))

	d := json.NewDecoder(&buf1)
	m := map[string]any{}
	for d.Decode(&m) == nil {
		bs, _ := json.Marshal(m)
		buf2.Write(bs)
		buf2.WriteByte('\n')
		clear(m)
	}

	return buf2.String()
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
