// Package logutil contains functionality for working with logs.
package logutil

import (
	"bufio"
	"errors"
	"io"
	"iter"
	"os"
	"strings"

	"github.com/pomerium/pomerium/internal/log"
)

// IterateLines iterates over all the lines of a log reader. The log reader
// will be closed after iteration.
func IterateLines(rc io.ReadCloser) iter.Seq[string] {
	return func(yield func(string) bool) {
		defer rc.Close()

		br := bufio.NewReader(rc)
		for {
			ln, err := br.ReadString('\n')

			// ln may not be empty even if there's an error, so we process ln
			// unconditionally

			// remove trailing newlines
			ln = strings.TrimRight(ln, "\r\n")
			// ignore empty strings
			if ln != "" {
				if !yield(ln) {
					return
				}
			}

			if errors.Is(err, io.EOF) || errors.Is(err, os.ErrClosed) {
				return
			} else if err != nil {
				log.Error().Err(err).Msg("logutil: unexpected error while reading log line")
			}
		}
	}
}
