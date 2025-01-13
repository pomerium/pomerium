package testenv

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"reflect"
	"regexp"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// LogRecorder captures logs from the test environment. It can be created at
// any time by calling [Environment.NewLogRecorder], and captures logs until
// one of Close(), Logs(), or Match() is called, which stops recording. See the
// documentation for each method for more details.
type LogRecorder struct {
	LogRecorderOptions
	t            testing.TB
	canceled     <-chan struct{}
	buf          *buffer
	recordedLogs []map[string]any

	removeGlobalWriterOnce func()
	collectLogsOnce        sync.Once
}

type LogRecorderOptions struct {
	filters        []func(map[string]any) bool
	skipCloseDelay bool
}

type LogRecorderOption func(*LogRecorderOptions)

func (o *LogRecorderOptions) apply(opts ...LogRecorderOption) {
	for _, op := range opts {
		op(o)
	}
}

// WithFilters applies one or more filter predicates to the logger. If there
// are filters present, they will be called in order when a log is received,
// and if any filter returns false for a given log, it will be discarded.
func WithFilters(filters ...func(map[string]any) bool) LogRecorderOption {
	return func(o *LogRecorderOptions) {
		o.filters = filters
	}
}

// WithSkipCloseDelay skips the 1.1 second delay before closing the recorder.
// This delay is normally required to ensure Envoy access logs are flushed,
// but can be skipped if not required.
func WithSkipCloseDelay() LogRecorderOption {
	return func(o *LogRecorderOptions) {
		o.skipCloseDelay = true
	}
}

type buffer struct {
	mu         *sync.Mutex
	underlying bytes.Buffer
	cond       *sync.Cond
	waiting    bool
	closed     bool
}

func newBuffer() *buffer {
	mu := &sync.Mutex{}
	return &buffer{
		mu:   mu,
		cond: sync.NewCond(mu),
	}
}

// Read implements io.ReadWriteCloser.
func (b *buffer) Read(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	for {
		n, err := b.underlying.Read(p)
		if errors.Is(err, io.EOF) && !b.closed {
			b.waiting = true
			b.cond.Wait()
			continue
		}
		return n, err
	}
}

// Write implements io.ReadWriteCloser.
func (b *buffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return 0, io.ErrClosedPipe
	}
	if b.waiting {
		b.waiting = false
		defer b.cond.Signal()
	}
	return b.underlying.Write(p)
}

// Close implements io.ReadWriteCloser.
func (b *buffer) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.closed = true
	b.cond.Signal()
	return nil
}

var _ io.ReadWriteCloser = (*buffer)(nil)

func (e *environment) NewLogRecorder(opts ...LogRecorderOption) *LogRecorder {
	options := LogRecorderOptions{}
	options.apply(opts...)
	lr := &LogRecorder{
		LogRecorderOptions: options,
		t:                  e.t,
		canceled:           e.Context().Done(),
		buf:                newBuffer(),
	}
	e.logWriter.Add(lr.buf)
	lr.removeGlobalWriterOnce = sync.OnceFunc(func() {
		// wait for envoy access logs, which flush on a 1 second interval
		if !lr.skipCloseDelay {
			time.Sleep(1100 * time.Millisecond)
		}
		e.logWriter.Remove(lr.buf)
	})
	context.AfterFunc(e.Context(), lr.removeGlobalWriterOnce)
	return lr
}

type (
	// OpenMap is an alias for map[string]any, and can be used to semantically
	// represent a map that must contain at least the given entries, but may
	// also contain additional entries.
	OpenMap = map[string]any
	// ClosedMap is a map[string]any that can be used to semantically represent
	// a map that must contain the given entries exactly, and no others.
	ClosedMap map[string]any
)

// Close stops the log recorder. After calling this method, Logs() or Match()
// can be called to inspect the logs that were captured.
func (lr *LogRecorder) Close() {
	lr.removeGlobalWriterOnce()
}

func (lr *LogRecorder) collectLogs(shouldClose bool) {
	if shouldClose {
		lr.removeGlobalWriterOnce()
		lr.buf.Close()
	}
	lr.collectLogsOnce.Do(func() {
		recordedLogs := []map[string]any{}
		scan := bufio.NewScanner(lr.buf)
		for scan.Scan() {
			log := scan.Bytes()
			m := map[string]any{}
			decoder := json.NewDecoder(bytes.NewReader(log))
			decoder.UseNumber()
			require.NoError(lr.t, decoder.Decode(&m))
			for _, filter := range lr.filters {
				if !filter(m) {
					continue
				}
			}
			recordedLogs = append(recordedLogs, m)
		}
		lr.recordedLogs = recordedLogs
	})
}

func (lr *LogRecorder) WaitForMatch(expectedLog map[string]any, timeout ...time.Duration) {
	lr.skipCloseDelay = true
	found := make(chan struct{})
	done := make(chan struct{})
	lr.filters = append(lr.filters, func(entry map[string]any) bool {
		select {
		case <-found:
		default:
			if matched, _ := match(expectedLog, entry, true); matched {
				close(found)
			}
		}
		return true
	})
	go func() {
		defer close(done)
		lr.collectLogs(false)
		lr.removeGlobalWriterOnce()
	}()
	if len(timeout) != 0 {
		select {
		case <-found:
		case <-time.After(timeout[0]):
			lr.t.Error("timed out waiting for log")
		case <-lr.canceled:
			lr.t.Error("canceled")
		}
	} else {
		select {
		case <-found:
		case <-lr.canceled:
			lr.t.Error("canceled")
		}
	}
	lr.buf.Close()
	<-done
}

// Logs stops the log recorder (if it is not already stopped), then returns
// the logs that were captured as structured map[string]any objects.
func (lr *LogRecorder) Logs() []map[string]any {
	lr.collectLogs(true)
	return lr.recordedLogs
}

func (lr *LogRecorder) DumpToFile(file string) {
	lr.collectLogs(true)
	f, err := os.Create(file)
	require.NoError(lr.t, err)
	enc := json.NewEncoder(f)
	for _, log := range lr.recordedLogs {
		_ = enc.Encode(log)
	}
	f.Close()
}

// Match stops the log recorder (if it is not already stopped), then asserts
// that the given expected logs were captured. The expected logs may contain
// partial or complete log entries. By default, logs must only match the fields
// given, and may contain additional fields that will be ignored.
//
// There are several special-case value types that can be used to customize the
// matching behavior, and/or simplify some common use cases, as follows:
//   - [OpenMap] and [ClosedMap] can be used to control matching logic
//   - [json.Number] will convert the actual value to a string before comparison
//   - [*tls.Certificate] or [*x509.Certificate] will expand to the fields that
//     would be logged for this certificate
func (lr *LogRecorder) Match(expectedLogs []map[string]any) {
	lr.collectLogs(true)
	for _, expectedLog := range expectedLogs {
		found := false
		highScore, highScoreIdxs := 0, []int{}
		for i, actualLog := range lr.recordedLogs {
			if ok, score := match(expectedLog, actualLog, true); ok {
				found = true
				break
			} else if score > highScore {
				highScore = score
				highScoreIdxs = []int{i}
			} else if score == highScore {
				highScoreIdxs = append(highScoreIdxs, i)
			}
		}
		if len(highScoreIdxs) > 0 {
			expectedLogBytes, _ := json.MarshalIndent(expectedLog, "", " ")
			if len(highScoreIdxs) == 1 {
				actualLogBytes, _ := json.MarshalIndent(lr.recordedLogs[highScoreIdxs[0]], "", " ")
				assert.True(lr.t, found, "expected log not found: \n%s\n\nclosest match:\n%s\n",
					string(expectedLogBytes), string(actualLogBytes))
			} else {
				closestMatches := []string{}
				for _, i := range highScoreIdxs {
					bytes, _ := json.MarshalIndent(lr.recordedLogs[i], "", " ")
					closestMatches = append(closestMatches, string(bytes))
				}
				assert.True(lr.t, found, "expected log not found: \n%s\n\nclosest matches:\n%s\n", string(expectedLogBytes), closestMatches)
			}
		} else {
			expectedLogBytes, _ := json.MarshalIndent(expectedLog, "", " ")
			assert.True(lr.t, found, "expected log not found: %s", string(expectedLogBytes))
		}
	}
}

func match(expected, actual map[string]any, open bool) (matched bool, score int) {
	for key, value := range expected {
		actualValue, ok := actual[key]
		if !ok {
			return false, score
		}
		score++

		switch actualValue := actualValue.(type) {
		case map[string]any:
			switch expectedValue := value.(type) {
			case ClosedMap:
				ok, s := match(expectedValue, actualValue, false)
				score += s * 2
				if !ok {
					return false, score
				}
			case OpenMap:
				ok, s := match(expectedValue, actualValue, true)
				score += s
				if !ok {
					return false, score
				}
			case *tls.Certificate, *Certificate, *x509.Certificate:
				var leaf *x509.Certificate
				switch expectedValue := expectedValue.(type) {
				case *tls.Certificate:
					leaf = expectedValue.Leaf
				case *Certificate:
					leaf = expectedValue.Leaf
				case *x509.Certificate:
					leaf = expectedValue
				}

				// keep logic consistent with controlplane.populateCertEventDict()
				expected := map[string]any{}
				if iss := leaf.Issuer.String(); iss != "" {
					expected["issuer"] = iss
				}
				if sub := leaf.Subject.String(); sub != "" {
					expected["subject"] = sub
				}
				sans := []string{}
				for _, dnsSAN := range leaf.DNSNames {
					sans = append(sans, "DNS:"+dnsSAN)
				}
				for _, uriSAN := range leaf.URIs {
					sans = append(sans, "URI:"+uriSAN.String())
				}
				if len(sans) > 0 {
					expected["subjectAltName"] = sans
				}

				ok, s := match(expected, actualValue, false)
				score += s
				if !ok {
					return false, score
				}
			default:
				return false, score
			}
		case string:
			switch value := value.(type) {
			case string:
				if value != actualValue {
					return false, score
				}
				score++
			case *regexp.Regexp:
				if !value.MatchString(actualValue) {
					return false, score
				}
				score++
			default:
				return false, score
			}
		case json.Number:
			if fmt.Sprint(value) != actualValue.String() {
				return false, score
			}
			score++
		default:
			// handle slices
			if reflect.TypeOf(actualValue).Kind() == reflect.Slice {
				if reflect.TypeOf(value) != reflect.TypeOf(actualValue) {
					return false, score
				}
				actualSlice := reflect.ValueOf(actualValue)
				expectedSlice := reflect.ValueOf(value)
				totalScore := 0
				for i := range min(actualSlice.Len(), expectedSlice.Len()) {
					if actualSlice.Index(i).Equal(expectedSlice.Index(i)) {
						totalScore++
					}
				}
				score += totalScore
			} else {
				panic(fmt.Sprintf("test bug: add check for type %T in assertMatchingLogs", actualValue))
			}
		}
	}
	if !open && len(expected) != len(actual) {
		return false, score
	}
	return true, score
}
