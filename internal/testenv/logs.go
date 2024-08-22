package testenv

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
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
	buf          *bytes.Buffer
	recordedLogs []map[string]any

	closeOnce       func()
	collectLogsOnce sync.Once
}

type LogRecorderOptions struct {
	filters []func(map[string]any) bool
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

func (e *environment) NewLogRecorder(opts ...LogRecorderOption) *LogRecorder {
	options := LogRecorderOptions{}
	options.apply(opts...)
	lr := &LogRecorder{
		LogRecorderOptions: options,
		t:                  e.t,
		buf:                &bytes.Buffer{},
	}
	e.logWriter.Add(lr.buf)
	lr.closeOnce = sync.OnceFunc(func() {
		// wait for envoy access logs, which flush on a 1 second interval
		time.Sleep(1100 * time.Millisecond)
		e.logWriter.Remove(lr.buf)
	})
	context.AfterFunc(e.ctx, lr.closeOnce)
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
	lr.closeOnce()
}

func (lr *LogRecorder) collectLogs() {
	lr.closeOnce()
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

// Logs stops the log recorder (if it is not already stopped), then returns
// the logs that were captured as structured map[string]any objects.
func (lr *LogRecorder) Logs() []map[string]any {
	lr.collectLogs()
	return lr.recordedLogs
}

// Match stops the log recorder (if it is not already stopped), then asserts
// that the given expected logs were captured. The expected logs may contain
// partial or complete log entries. By default, logs must only match the fields
// given, and may contain additional fields that will be ignored. For details,
// see [OpenMap] and [ClosedMap]. As a special case, using [json.Number] as the
// expected value will convert the actual value to a string before comparison.
func (lr *LogRecorder) Match(expectedLogs []map[string]any) {
	lr.collectLogs()
	var match func(expected, actual map[string]any, open bool) (bool, int)
	match = func(expected, actual map[string]any, open bool) (bool, int) {
		score := 0
		for key, value := range expected {
			actualValue, ok := actual[key]
			if !ok {
				return false, score
			}
			score++

			switch actualValue := actualValue.(type) {
			case map[string]any:
				switch value := value.(type) {
				case ClosedMap:
					ok, s := match(value, actualValue, false)
					score += s * 2
					if !ok {
						return false, score
					}
				case OpenMap:
					ok, s := match(value, actualValue, true)
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
				default:
					return false, score
				}
			case json.Number:
				if fmt.Sprint(value) != actualValue.String() {
					return false, score
				}
				score++
			default:
				panic(fmt.Sprintf("test bug: add check for type %T in assertMatchingLogs", actualValue))
			}
		}
		if !open && len(expected) != len(actual) {
			return false, score
		}
		return true, score
	}

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
