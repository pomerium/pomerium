package log_test

import (
	"context"
	"errors"
	"flag"
	"time"

	"github.com/rs/zerolog"

	"github.com/pomerium/pomerium/internal/log"
)

// setup would normally be an init() function, however, there seems
// to be something awry with the testing framework when we set the
// global Logger from an init()
func setup() {
	// UNIX Time is faster and smaller than most timestamps
	// If you set zerolog.TimeFieldFormat to an empty string,
	// logs will write with UNIX time
	zerolog.TimeFieldFormat = ""
	// In order to always output a static time to stdout for these
	// examples to pass, we need to override zerolog.TimestampFunc
	// and log.Logger globals -- you would not normally need to do this
	zerolog.TimestampFunc = func() time.Time {
		return time.Date(2008, 1, 8, 17, 5, 5, 0, time.UTC)
	}
	log.DisableDebug()
}

// Simple logging example using the Print function in the log package
// Note that both Print and Printf are at the debug log level by default
func ExamplePrint() {
	setup()

	log.Print("hello world")
	// Output: {"level":"debug","time":1199811905,"message":"hello world"}
}

func ExampleWith() {
	setup()
	sublog := log.With().Str("foo", "bar").Logger()
	sublog.Debug().Msg("hello world")
	// Output: {"level":"debug","foo":"bar","time":1199811905,"message":"hello world"}
}

// Simple logging example using the Printf function in the log package
func ExamplePrintf() {
	setup()

	log.Printf("hello %s", "world")
	// Output: {"level":"debug","time":1199811905,"message":"hello world"}
}

// Example of a log with no particular "level"
func ExampleLog() {
	setup()
	log.Log(context.Background()).Msg("hello world")

	// Output: {"time":1199811905,"message":"hello world"}
}

// Example of a log at a particular "level" (in this case, "debug")
func ExampleDebug() {
	setup()
	log.Debug(context.Background()).Msg("hello world")

	// Output: {"level":"debug","time":1199811905,"message":"hello world"}
}

// Example of a log at a particular "level" (in this case, "info")
func ExampleInfo() {
	setup()
	log.Info(context.Background()).Msg("hello world")

	// Output: {"level":"info","time":1199811905,"message":"hello world"}
}

// Example of a log at a particular "level" (in this case, "warn")
func ExampleWarn() {
	setup()
	log.Warn(context.Background()).Msg("hello world")

	// Output: {"level":"warn","time":1199811905,"message":"hello world"}
}

// Example of a log at a particular "level" (in this case, "error")
func ExampleError() {
	setup()
	log.Error(context.Background()).Msg("hello world")

	// Output: {"level":"error","time":1199811905,"message":"hello world"}
}

// Example of a log at a particular "level" (in this case, "fatal")
func ExampleFatal() {
	setup()
	err := errors.New("a repo man spends his life getting into tense situations")
	service := "myservice"

	log.Fatal().
		Err(err).
		Str("service", service).
		Msg("Cannot start")

	// Outputs: {"level":"fatal","time":1199811905,"error":"a repo man spends his life getting into tense situations","service":"myservice","message":"Cannot start myservice"}
}

// This example uses command-line flags to demonstrate various outputs
// depending on the chosen log level.
func Example() {
	setup()
	debug := flag.Bool("debug", false, "sets log level to debug")

	flag.Parse()

	// Default level for this example is info, unless debug flag is present
	zerolog.SetGlobalLevel(zerolog.InfoLevel)
	if *debug {
		zerolog.SetGlobalLevel(zerolog.DebugLevel)
	}

	log.Debug(context.Background()).Msg("This message appears only when log level set to Debug")
	log.Info(context.Background()).Msg("This message appears when log level set to Debug or Info")

	if e := log.Debug(context.Background()); e.Enabled() {
		// Compute log output only if enabled.
		value := "bar"
		e.Str("foo", value).Msg("some debug message")
	}

	// Output: {"level":"info","time":1199811905,"message":"This message appears when log level set to Debug or Info"}
}

func ExampleSetLevel() {
	setup()
	log.SetLevel(zerolog.InfoLevel)
	log.Debug(context.Background()).Msg("Debug")
	log.Info(context.Background()).Msg("Debug or Info")
	log.SetLevel(zerolog.WarnLevel)
	log.Debug(context.Background()).Msg("Debug")
	log.Info(context.Background()).Msg("Debug or Info")
	log.Warn(context.Background()).Msg("Debug or Info or Warn")
	log.SetLevel(zerolog.ErrorLevel)
	log.Debug(context.Background()).Msg("Debug")
	log.Info(context.Background()).Msg("Debug or Info")
	log.Warn(context.Background()).Msg("Debug or Info or Warn")
	log.Error(context.Background()).Msg("Debug or Info or Warn or Error")
	log.SetLevel(zerolog.DebugLevel)
	log.Debug(context.Background()).Msg("Debug")

	// Output:
	// {"level":"info","time":1199811905,"message":"Debug or Info"}
	// {"level":"warn","time":1199811905,"message":"Debug or Info or Warn"}
	// {"level":"error","time":1199811905,"message":"Debug or Info or Warn or Error"}
	// {"level":"debug","time":1199811905,"message":"Debug"}
}

func ExampleContext() {
	setup()

	bg := context.Background()
	ctx1 := log.WithContext(bg, func(c zerolog.Context) zerolog.Context {
		return c.Str("param_one", "one")
	})
	ctx2 := log.WithContext(ctx1, func(c zerolog.Context) zerolog.Context {
		return c.Str("param_two", "two")
	})

	log.Warn(bg).Str("non_context_param", "value").Msg("background")
	log.Warn(ctx1).Str("non_context_param", "value").Msg("first")
	log.Warn(ctx2).Str("non_context_param", "value").Msg("second")

	for i := 0; i < 10; i++ {
		ctx1 = log.WithContext(ctx1, func(c zerolog.Context) zerolog.Context {
			return c.Int("counter", i)
		})
	}
	log.Info(ctx1).Str("non_ctx_param", "value").Msg("after counter")

	/*
		{"level":"warn","ctx":"one","param":"first","time":1199811905,"message":"first"}
		{"level":"warn","ctx":"two","param":"second","time":1199811905,"message":"second"}
		{"level":"warn","param":"third","time":1199811905,"message":"third"}
	*/
}
