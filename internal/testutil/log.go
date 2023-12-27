package testutil

import (
	"bytes"
	"encoding/json"
	"io"
	"sync"
	"testing"

	"github.com/pomerium/pomerium/internal/log"
)

// CaptureLogs captures any logs made during the test. Time will be stripped.
// Any tests that use it should not be run in parallel.
func CaptureLogs(t *testing.T, f func()) string {
	t.Helper()

	pr, pw := io.Pipe()
	log.Writer.Add(pw)
	defer log.Writer.Remove(pw)

	var buf bytes.Buffer
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()

		d := json.NewDecoder(pr)
		for {
			var m map[string]any
			if d.Decode(&m) != nil {
				break
			}
			delete(m, "time")
			bs, _ := json.Marshal(m)
			buf.Write(bs)
			buf.WriteByte('\n')
		}
	}()
	go func() {
		defer wg.Done()

		f()

		pw.Close()
	}()
	wg.Wait()

	return buf.String()
}
