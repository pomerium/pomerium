// Adapted from https://golang.org/src/log/example_test.go
// Copyright 2013 The Go Authors. See 3RD-PARTY file for license.

package log_test

import (
	"bytes"
	"fmt"
	stdlog "log"
	"os"

	"github.com/pomerium/pomerium/internal/log"
	"github.com/rs/zerolog"
)

func ExampleLogger() {
	log.Logger = zerolog.New(os.Stdout).With().Str("level-logging?", "yep!").Logger()

	var (
		buf    bytes.Buffer
		logger = stdlog.New(&log.StdLogWrapper{Logger: &log.Logger}, "", 0)
	)

	logger.Print("Hello logger!")
	log.SetDebugMode()

	logger.Print("Debug")

	fmt.Print(&buf)
	// Output:
	// {"level":"error","level-logging?":"yep!","message":"Hello logger!"}
	//[90m<nil>[0m [1m[31mERR[0m[0m Debug [36mlevel-logging?=[0myep!

}
