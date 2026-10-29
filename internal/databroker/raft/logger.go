package raft

import (
	"fmt"
	"io"
	stdlog "log"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/hashicorp/go-hclog"
	"github.com/rs/zerolog"

	"github.com/pomerium/pomerium/internal/log"
)

const loggerNameField = "component"

// logger is an hclog.Logger that writes to a zerolog logger without ever
// emitting a key twice. Args whose keys collide with fields the logger
// writes itself are kept under a "raft-" prefixed key, and a repeated key
// keeps its last value.
type logger struct {
	zl   zerolog.Logger
	name string
	args []any
}

// newLogger creates a new hclog.Logger for raft that writes to the global
// logger with the given name as its component.
func newLogger(name string) hclog.Logger {
	return &logger{zl: log.Logger().With().Logger(), name: name}
}

func (l *logger) Log(level hclog.Level, msg string, args ...any) {
	evt := l.zl.WithLevel(toZerologLevel(level))
	if evt == nil {
		return
	}
	evt.Str(loggerNameField, l.name).Fields(l.fields(args)).Msg(msg)
}

func (l *logger) Trace(msg string, args ...any) { l.Log(hclog.Trace, msg, args...) }
func (l *logger) Debug(msg string, args ...any) { l.Log(hclog.Debug, msg, args...) }
func (l *logger) Info(msg string, args ...any)  { l.Log(hclog.Info, msg, args...) }
func (l *logger) Warn(msg string, args ...any)  { l.Log(hclog.Warn, msg, args...) }
func (l *logger) Error(msg string, args ...any) { l.Log(hclog.Error, msg, args...) }

func (l *logger) IsTrace() bool { return l.GetLevel() == hclog.Trace }
func (l *logger) IsDebug() bool { return l.GetLevel() <= hclog.Debug }
func (l *logger) IsInfo() bool  { return l.GetLevel() <= hclog.Info }
func (l *logger) IsWarn() bool  { return l.GetLevel() <= hclog.Warn }
func (l *logger) IsError() bool { return l.GetLevel() <= hclog.Error }

func (l *logger) ImpliedArgs() []any {
	return l.args
}

func (l *logger) With(args ...any) hclog.Logger {
	return &logger{zl: l.zl, name: l.name, args: slices.Concat(l.args, pairs(args))}
}

func (l *logger) Name() string {
	return l.name
}

func (l *logger) Named(name string) hclog.Logger {
	if l.name != "" {
		name = l.name + "." + name
	}
	return l.ResetNamed(name)
}

func (l *logger) ResetNamed(name string) hclog.Logger {
	return &logger{zl: l.zl, name: name, args: l.args}
}

func (l *logger) SetLevel(level hclog.Level) {
	l.zl = l.zl.Level(toZerologLevel(level))
}

func (l *logger) GetLevel() hclog.Level {
	switch max(l.zl.GetLevel(), zerolog.GlobalLevel()) {
	case zerolog.TraceLevel:
		return hclog.Trace
	case zerolog.DebugLevel:
		return hclog.Debug
	case zerolog.InfoLevel:
		return hclog.Info
	case zerolog.WarnLevel:
		return hclog.Warn
	case zerolog.ErrorLevel, zerolog.FatalLevel, zerolog.PanicLevel:
		return hclog.Error
	case zerolog.NoLevel:
		return hclog.NoLevel
	default:
		return hclog.Off
	}
}

func (l *logger) StandardLogger(opts *hclog.StandardLoggerOptions) *stdlog.Logger {
	return stdlog.New(l.StandardWriter(opts), "", 0)
}

func (l *logger) StandardWriter(_ *hclog.StandardLoggerOptions) io.Writer {
	return l.zl.With().Str(loggerNameField, l.name).Fields(l.fields(nil)).Logger()
}

// fields returns the implied args followed by args as a zerolog field list.
func (l *logger) fields(args []any) []any {
	kvs := slices.Concat(l.args, pairs(args))
	fields := make([]any, 0, len(kvs))
	idx := make(map[string]int, len(kvs)/2)
	for i := 0; i < len(kvs); i += 2 {
		k, ok := kvs[i].(string)
		if !ok {
			k = fmt.Sprint(kvs[i])
		}
		// zerolog writes invalid UTF-8 as U+FFFD, which could make two keys equal
		k = strings.ToValidUTF8(k, string(utf8.RuneError))
		switch k {
		case zerolog.TimestampFieldName, zerolog.LevelFieldName, zerolog.MessageFieldName, loggerNameField:
			k = "raft-" + k
		}
		v := fieldValue(kvs[i+1])
		if j, ok := idx[k]; ok {
			fields[j+1] = v
			continue
		}
		idx[k] = len(fields)
		fields = append(fields, k, v)
	}
	return fields
}

// fieldValue returns v as its string when it implements fmt.Stringer, except
// for the types zerolog already formats.
func fieldValue(v any) any {
	switch v.(type) {
	case time.Duration, time.Time, error:
		return v
	case fmt.Stringer:
		return fmt.Sprint(v)
	}
	return v
}

// pairs returns args with an odd trailing value keyed by hclog.MissingKey.
func pairs(args []any) []any {
	if len(args)%2 == 0 {
		return args
	}
	return append(slices.Clone(args[:len(args)-1]), hclog.MissingKey, args[len(args)-1])
}

func toZerologLevel(level hclog.Level) zerolog.Level {
	switch level {
	case hclog.Trace:
		return zerolog.TraceLevel
	case hclog.Debug:
		return zerolog.DebugLevel
	case hclog.Info:
		return zerolog.InfoLevel
	case hclog.Warn:
		return zerolog.WarnLevel
	case hclog.Error:
		return zerolog.ErrorLevel
	case hclog.NoLevel:
		return zerolog.NoLevel
	default:
		return zerolog.Disabled
	}
}
