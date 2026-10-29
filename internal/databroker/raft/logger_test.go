package raft

import (
	"bufio"
	"bytes"
	"encoding/json"
	"maps"
	"slices"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/hashicorp/go-hclog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"hegel.dev/go/hegel"

	"github.com/pomerium/pomerium/internal/log"
)

func TestLogger(t *testing.T) {
	for _, name := range []string{"raft-node", "raft-transport"} {
		t.Run(name, func(t *testing.T) {
			var buf bytes.Buffer
			log.Writer.Add(&buf)
			l := newLogger(name)
			l.Warn("failed to contact", "server-id", "pomerium-1", "time", 500*time.Millisecond)
			l.With("time", 500*time.Millisecond).Info("with")
			l.Named("sub").Info("named", "time", 500*time.Millisecond)
			l.Log(hclog.Error, "reserved", "level", "x", "message", "y", "component", "z")
			l.With("server-id", "pomerium-1").Info("with repeated", "server-id", "pomerium-2")
			log.Writer.Remove(&buf)

			lines := map[string]map[string]any{}
			s := bufio.NewScanner(&buf)
			for s.Scan() {
				var m map[string]any
				require.NoError(t, json.Unmarshal(s.Bytes(), &m), "line: %s", s.Text())
				msg, _ := m["message"].(string)
				switch msg {
				case "failed to contact", "with", "named", "reserved", "with repeated":
				default:
					continue
				}
				assert.Empty(t, duplicateKeys(t, s.Bytes()), "line: %s", s.Text())
				lines[msg] = m
			}
			require.NoError(t, s.Err())
			require.Len(t, lines, 5)

			for msg, m := range lines {
				ts, ok := m["time"].(string)
				if assert.True(t, ok, "%s: time must be the timestamp string, got %v", msg, m["time"]) {
					_, err := time.Parse(time.RFC3339, ts)
					assert.NoError(t, err, msg)
				}
			}

			assert.Equal(t, "warn", lines["failed to contact"]["level"])
			assert.Equal(t, name, lines["failed to contact"]["component"])
			assert.Equal(t, "pomerium-1", lines["failed to contact"]["server-id"])
			assert.Equal(t, 500.0, lines["failed to contact"]["raft-time"])

			assert.Equal(t, name, lines["with"]["component"])
			assert.Equal(t, 500.0, lines["with"]["raft-time"])

			assert.Equal(t, name+".sub", lines["named"]["component"])
			assert.Equal(t, 500.0, lines["named"]["raft-time"])

			assert.Equal(t, "error", lines["reserved"]["level"])
			assert.Equal(t, name, lines["reserved"]["component"])
			assert.Equal(t, "x", lines["reserved"]["raft-level"])
			assert.Equal(t, "y", lines["reserved"]["raft-message"])
			assert.Equal(t, "z", lines["reserved"]["raft-component"])

			assert.Equal(t, "pomerium-2", lines["with repeated"]["server-id"])
		})
	}
}

// duplicateKeys returns the top-level keys that occur more than once in the
// given JSON object.
func duplicateKeys(t testing.TB, line []byte) []string {
	t.Helper()

	d := json.NewDecoder(bytes.NewReader(line))
	_, err := d.Token() // {
	require.NoError(t, err)

	seen := map[string]bool{}
	var dups []string
	for d.More() {
		tok, err := d.Token()
		require.NoError(t, err)
		key := tok.(string)
		if seen[key] {
			dups = append(dups, key)
		}
		seen[key] = true

		var v json.RawMessage
		require.NoError(t, d.Decode(&v))
	}
	return dups
}

func TestLoggerNoDuplicateKeys(t *testing.T) {
	levels := map[hclog.Level]string{
		hclog.Debug:   "debug",
		hclog.Info:    "info",
		hclog.Warn:    "warn",
		hclog.Error:   "error",
		hclog.NoLevel: "",
	}
	key := hegel.OneOf(
		hegel.Map(hegel.SampledFrom(loggerTestKeys), func(s string) any { return s }),
		hegel.Map(hegel.Text().MaxSize(3), func(s string) any { return s }),
		// a small alphabet of bytes, some not valid UTF-8 on their own
		hegel.Map(hegel.Lists(hegel.SampledFrom([]byte("a\xc3\xa9\x80\xff"))).MaxSize(2), func(b []byte) any { return string(b) }),
		hegel.Map(hegel.Integers(-1, 1), func(i int) any { return i }),
	)
	value := hegel.OneOf(
		key,
		hegel.Map(hegel.Integers(-1000, 1000), func(i int) any { return time.Duration(i) * time.Millisecond }),
		hegel.Map(hegel.Booleans(), func(b bool) any { return b }),
		hegel.Just[any](nil),
	)
	drawArgs := func(ht *hegel.T) []any {
		var args []any
		for range hegel.Draw(ht, hegel.Integers(0, 4)) {
			args = append(args, hegel.Draw(ht, key), hegel.Draw(ht, value))
		}
		if hegel.Draw(ht, hegel.Booleans()) {
			args = append(args, hegel.Draw(ht, value))
		}
		return args
	}

	hegel.Test(t, func(ht *hegel.T) {
		name := hegel.Draw(ht, hegel.Text().MaxSize(5))
		l := newLogger(name)
		for range hegel.Draw(ht, hegel.Integers(0, 3)) {
			switch hegel.Draw(ht, hegel.SampledFrom([]string{"With", "Named", "ResetNamed"})) {
			case "With":
				l = l.With(drawArgs(ht)...)
			case "Named":
				n := hegel.Draw(ht, hegel.Text().MaxSize(5))
				l = l.Named(n)
				if name != "" {
					n = name + "." + n
				}
				name = n
			case "ResetNamed":
				name = hegel.Draw(ht, hegel.Text().MaxSize(5))
				l = l.ResetNamed(name)
			}
		}
		msg := hegel.Draw(ht, hegel.Text())
		callArgs := drawArgs(ht)

		var emit func()
		var wantLevel, wantMsg string
		if hegel.Draw(ht, hegel.Booleans()) {
			level := hegel.Draw(ht, hegel.SampledFrom(slices.Collect(maps.Keys(levels))))
			wantLevel, wantMsg = levels[level], msg
			emit = func() { l.Log(level, msg, callArgs...) }
		} else {
			// the standard writer logs without a level and without one trailing newline
			wantLevel, wantMsg = "", strings.TrimSuffix(msg, "\n")
			emit = func() { _, _ = l.With(callArgs...).StandardWriter(nil).Write([]byte(msg)) }
		}

		lines := captureLogLines(ht, emit)
		require.Len(ht, lines, 1)
		assert.True(ht, utf8.Valid(lines[0]), "line: %q", lines[0])
		assert.Empty(ht, duplicateKeys(ht, lines[0]), "line: %s", lines[0])

		var m map[string]any
		require.NoError(ht, json.Unmarshal(lines[0], &m))
		ts, _ := m["time"].(string)
		_, err := time.Parse(time.RFC3339, ts)
		assert.NoError(ht, err, "time must be the timestamp, got %v", m["time"])
		if wantLevel == "" {
			assert.NotContains(ht, m, "level")
		} else {
			assert.Equal(ht, wantLevel, m["level"])
		}
		if wantMsg == "" {
			assert.NotContains(ht, m, "message")
		} else {
			assert.Equal(ht, wantMsg, m["message"])
		}
		assert.Equal(ht, name, m["component"])
	}, hegel.WithTestCases(1000))
}

func TestLoggerKeepsArgs(t *testing.T) {
	key := hegel.OneOf(
		hegel.SampledFrom(loggerTestKeys),
		hegel.Text().MaxSize(3),
	)
	pairs := hegel.Lists(hegel.Lists(hegel.OneOf(key, hegel.Text())).MinSize(2).MaxSize(2)).MaxSize(4)
	flatten := func(ps [][]string) []any {
		var kvs []any
		for _, p := range ps {
			kvs = append(kvs, p[0], p[1])
		}
		return kvs
	}

	hegel.Test(t, func(ht *hegel.T) {
		// args named like a field the logger writes are expected under a
		// "raft-" prefixed key, and a repeated key with its last value
		want := map[string]any{}
		add := func(kvs []any) {
			for i := 0; i < len(kvs); i += 2 {
				k := kvs[i].(string)
				switch k {
				case "time", "level", "message", "component":
					k = "raft-" + k
				}
				want[k] = kvs[i+1]
			}
		}

		l := newLogger("raft-node")
		for range hegel.Draw(ht, hegel.Integers(0, 2)) {
			kvs := flatten(hegel.Draw(ht, pairs))
			add(kvs)
			l = l.With(kvs...)
		}
		kvs := flatten(hegel.Draw(ht, pairs))
		add(kvs)

		lines := captureLogLines(ht, func() { l.Info("args", kvs...) })
		require.Len(ht, lines, 1)

		var m map[string]any
		require.NoError(ht, json.Unmarshal(lines[0], &m))
		for _, k := range []string{"time", "level", "message", "component"} {
			delete(m, k)
		}
		assert.Equal(ht, want, m)
	})
}

// loggerTestKeys are arg keys that collide with fields the logger writes
// or with their renamed forms.
var loggerTestKeys = []string{
	"time", "level", "message", "component",
	"raft-time", "raft-level", "raft-message", "raft-component",
	hclog.MissingKey,
}

// captureLogLines returns the lines fn writes to the global logger.
func captureLogLines(t testing.TB, fn func()) [][]byte {
	t.Helper()

	var buf bytes.Buffer
	log.Writer.Add(&buf)
	fn()
	log.Writer.Remove(&buf)

	var lines [][]byte
	s := bufio.NewScanner(&buf)
	for s.Scan() {
		lines = append(lines, slices.Clone(s.Bytes()))
	}
	require.NoError(t, s.Err())
	return lines
}
