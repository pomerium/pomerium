package log_test

import (
	"context"
	"errors"
	"flag"
	"os"
	"time"

	"github.com/rs/zerolog"
	zerologlog "github.com/rs/zerolog/log"

	"github.com/pomerium/pomerium/internal/log"
)

func captureOutput(f func()) {
	// In order to always output a static time to stdout for these
	// examples to pass, we need to override zerolog.TimestampFunc
	// and log.Logger globals -- you would not normally need to do this
	originalTimestampFunc := zerolog.TimestampFunc
	zerolog.TimestampFunc = func() time.Time {
		return time.Date(2008, 1, 8, 17, 5, 5, 0, time.UTC)
	}

	originalLogger := zerologlog.Logger
	newLogger := originalLogger.
		Output(os.Stdout).
		Level(zerolog.TraceLevel)
	zerologlog.Logger = newLogger
	zerolog.DefaultContextLogger = &newLogger

	f()

	zerolog.DefaultContextLogger = &originalLogger
	zerolog.TimestampFunc = originalTimestampFunc
	zerologlog.Logger = originalLogger
}

// Simple logging example using the Print function in the log package
// Note that both Print and Printf are at the debug log level by default
func ExamplePrint() {
	captureOutput(func() {
		log.Print("hello world")
	})
	// Output: {"level":"debug","time":"2008-01-08T17:05:05Z","message":"hello world"}
}

func ExampleWith() {
	captureOutput(func() {
		sublog := log.With().Str("foo", "bar").Logger()
		sublog.Debug().Msg("hello world")
	})
	// Output: {"level":"debug","foo":"bar","time":"2008-01-08T17:05:05Z","message":"hello world"}
}

// Simple logging example using the Printf function in the log package
func ExamplePrintf() {
	captureOutput(func() {
		log.Printf("hello %s", "world")
	})
	// Output: {"level":"debug","time":"2008-01-08T17:05:05Z","message":"hello world"}
}

// Example of a log at a particular "level" (in this case, "debug")
func ExampleDebug() {
	captureOutput(func() {
		log.Debug().Msg("hello world")
	})
	// Output: {"level":"debug","time":"2008-01-08T17:05:05Z","message":"hello world"}
}

// Example of a log at a particular "level" (in this case, "info")
func ExampleInfo() {
	captureOutput(func() {
		log.Info().Msg("hello world")
	})
	// Output: {"level":"info","time":"2008-01-08T17:05:05Z","message":"hello world"}
}

// Example of a log at a particular "level" (in this case, "error")
func ExampleError() {
	captureOutput(func() {
		log.Error().Msg("hello world")
	})
	// Output: {"level":"error","time":"2008-01-08T17:05:05Z","message":"hello world"}
}

// Example of a log at a particular "level" (in this case, "fatal")
func ExampleFatal() {
	captureOutput(func() {
		err := errors.New("a repo man spends his life getting into tense situations")
		service := "myservice"

		log.Fatal().
			Err(err).
			Str("service", service).
			Msg("Cannot start")
	})
	// Outputs: {"level":"fatal","time":"2008-01-08T17:05:05Z","error":"a repo man spends his life getting into tense situations","service":"myservice","message":"Cannot start myservice"}
}

// This example uses command-line flags to demonstrate various outputs
// depending on the chosen log level.
func Example() {
	captureOutput(func() {
		debug := flag.Bool("debug", false, "sets log level to debug")

		flag.Parse()

		// Default level for this example is info, unless debug flag is present
		zerolog.SetGlobalLevel(zerolog.InfoLevel)
		if *debug {
			zerolog.SetGlobalLevel(zerolog.DebugLevel)
		}

		log.Debug().Msg("This message appears only when log level set to Debug")
		log.Info().Msg("This message appears when log level set to Debug or Info")

		if e := log.Debug(); e.Enabled() {
			// Compute log output only if enabled.
			value := "bar"
			e.Str("foo", value).Msg("some debug message")
		}
	})
	// Output: {"level":"info","time":"2008-01-08T17:05:05Z","message":"This message appears when log level set to Debug or Info"}
}

func ExampleSetLevel() {
	captureOutput(func() {
		log.SetLevel(zerolog.InfoLevel)
		log.Debug().Msg("Debug")
		log.Info().Msg("Debug or Info")
		log.SetLevel(zerolog.WarnLevel)
		log.Debug().Msg("Debug")
		log.Info().Msg("Debug or Info")
		log.SetLevel(zerolog.ErrorLevel)
		log.Debug().Msg("Debug")
		log.Info().Msg("Debug or Info")
		log.Error().Msg("Debug or Info or Warn or Error")
		log.SetLevel(zerolog.DebugLevel)
		log.Debug().Msg("Debug")
	})
	// Output:
	// {"level":"info","time":"2008-01-08T17:05:05Z","message":"Debug or Info"}
	// {"level":"error","time":"2008-01-08T17:05:05Z","message":"Debug or Info or Warn or Error"}
	// {"level":"debug","time":"2008-01-08T17:05:05Z","message":"Debug"}
}

func ExampleContext() {
	captureOutput(func() {
		bg := context.Background()
		ctx1 := log.WithContext(bg, func(c zerolog.Context) zerolog.Context {
			return c.Str("param-one", "one")
		})
		ctx2 := log.WithContext(ctx1, func(c zerolog.Context) zerolog.Context {
			return c.Str("param-two", "two")
		})

		log.Ctx(bg).Error().Str("non-context-param", "value").Msg("background")
		log.Ctx(ctx1).Error().Str("non-context-param", "value").Msg("first")
		log.Ctx(ctx2).Error().Str("non-context-param", "value").Msg("second")

		for i := 0; i < 10; i++ {
			ctx1 = log.WithContext(ctx1, func(c zerolog.Context) zerolog.Context {
				return c.Int("counter", i)
			})
		}
		log.Ctx(ctx1).Info().Str("non-ctx-param", "value").Msg("after counter")
	})
	// Output:
	// {"level":"error","non-context-param":"value","time":"2008-01-08T17:05:05Z","message":"background"}
	// {"level":"error","param-one":"one","non-context-param":"value","time":"2008-01-08T17:05:05Z","message":"first"}
	// {"level":"error","param-one":"one","param-two":"two","non-context-param":"value","time":"2008-01-08T17:05:05Z","message":"second"}
	// {"level":"info","param-one":"one","counter":0,"counter":1,"counter":2,"counter":3,"counter":4,"counter":5,"counter":6,"counter":7,"counter":8,"counter":9,"non-ctx-param":"value","time":"2008-01-08T17:05:05Z","message":"after counter"}
}
