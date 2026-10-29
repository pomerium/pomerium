package raft

import (
	"bufio"
	"bytes"
	"encoding/json"
	"slices"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/raft"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"hegel.dev/go/hegel"

	"github.com/pomerium/pomerium/internal/log"
)

func TestLogger(t *testing.T) {
	for _, name := range []string{"raft-node", "raft-transport"} {
		t.Run(name, func(t *testing.T) {
			l := newLogger(name)
			lines := captureLogLines(t, func() {
				l.Warn("failed to contact", "server-id", "pomerium-1", "time", 500*time.Millisecond)
				l.With("time", 500*time.Millisecond).Info("with")
				l.Named("sub").Info("named", "time", 500*time.Millisecond)
				l.Log(hclog.Error, "reserved", "level", "x", "message", "y", "component", "z")
				l.With("server-id", "pomerium-1").Info("with repeated", "server-id", "pomerium-2")
			})
			require.Len(t, lines, 5)

			logged := map[string]map[string]any{}
			for _, line := range lines {
				m := decodeLogLine(t, line)
				assertTimestamp(t, m)
				msg, _ := m["message"].(string)
				logged[msg] = m
			}

			assert.Equal(t, "warn", logged["failed to contact"]["level"])
			assert.Equal(t, name, logged["failed to contact"]["component"])
			assert.Equal(t, "pomerium-1", logged["failed to contact"]["server-id"])
			assert.Equal(t, 500.0, logged["failed to contact"]["raft-time"])

			assert.Equal(t, name, logged["with"]["component"])
			assert.Equal(t, 500.0, logged["with"]["raft-time"])

			assert.Equal(t, name+".sub", logged["named"]["component"])
			assert.Equal(t, 500.0, logged["named"]["raft-time"])

			assert.Equal(t, "error", logged["reserved"]["level"])
			assert.Equal(t, name, logged["reserved"]["component"])
			assert.Equal(t, "x", logged["reserved"]["raft-level"])
			assert.Equal(t, "y", logged["reserved"]["raft-message"])
			assert.Equal(t, "z", logged["reserved"]["raft-component"])

			assert.Equal(t, "pomerium-2", logged["with repeated"]["server-id"])
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
	levels := []struct {
		level hclog.Level
		name  string
	}{
		{hclog.Debug, "debug"},
		{hclog.Info, "info"},
		{hclog.Warn, "warn"},
		{hclog.Error, "error"},
		{hclog.NoLevel, ""},
	}
	key := hegel.OneOf(
		asAny(hegel.SampledFrom(loggerTestKeys)),
		asAny(hegel.Text().MaxSize(3)),
		// a small alphabet of bytes, some not valid UTF-8 on their own
		hegel.Map(hegel.Lists(hegel.SampledFrom([]byte("a\xc3\xa9\x80\xff"))).MaxSize(2), func(b []byte) any { return string(b) }),
		asAny(hegel.Integers(-1, 1)),
	)
	value := hegel.OneOf(
		key,
		hegel.Map(hegel.Integers(-1000, 1000), func(i int) any { return time.Duration(i) * time.Millisecond }),
		asAny(hegel.Booleans()),
		hegel.Just[any](nil),
	)
	drawArgs := func(ht *hegel.T) []any {
		args := drawKVs(ht, key, value)
		if hegel.Draw(ht, hegel.Booleans()) {
			args = append(args, hegel.Draw(ht, value))
		}
		return args
	}
	nameGen := hegel.Text().MaxSize(5)

	hegel.Test(t, func(ht *hegel.T) {
		name := hegel.Draw(ht, nameGen)
		l := newLogger(name)
		for range hegel.Draw(ht, hegel.Integers(0, 3)) {
			switch hegel.Draw(ht, hegel.SampledFrom([]string{"With", "Named", "ResetNamed"})) {
			case "With":
				l = l.With(drawArgs(ht)...)
			case "Named":
				n := hegel.Draw(ht, nameGen)
				l = l.Named(n)
				if name != "" {
					n = name + "." + n
				}
				name = n
			case "ResetNamed":
				name = hegel.Draw(ht, nameGen)
				l = l.ResetNamed(name)
			}
		}
		msg := hegel.Draw(ht, hegel.Text())
		callArgs := drawArgs(ht)

		var emit func()
		var wantLevel, wantMsg string
		if hegel.Draw(ht, hegel.Booleans()) {
			level := hegel.Draw(ht, hegel.SampledFrom(levels))
			wantLevel, wantMsg = level.name, msg
			emit = func() { l.Log(level.level, msg, callArgs...) }
		} else {
			// the standard writer logs without a level and without one trailing newline
			wantLevel, wantMsg = "", strings.TrimSuffix(msg, "\n")
			emit = func() { _, _ = l.With(callArgs...).StandardWriter(nil).Write([]byte(msg)) }
		}

		lines := captureLogLines(ht, emit)
		require.Len(ht, lines, 1)
		m := decodeLogLine(ht, lines[0])
		assertTimestamp(ht, m)
		assertField(ht, m, "level", wantLevel)
		assertField(ht, m, "message", wantMsg)
		assert.Equal(ht, name, m["component"])
	}, hegel.WithTestCases(1000))
}

func TestLoggerKeepsArgs(t *testing.T) {
	key := asAny(hegel.OneOf(hegel.SampledFrom(loggerTestKeys), hegel.Text().MaxSize(3)))
	value := asAny(hegel.OneOf(hegel.SampledFrom(loggerTestKeys), hegel.Text()))

	hegel.Test(t, func(ht *hegel.T) {
		// args named like a field the logger writes are expected under a
		// "raft-" prefixed key, and a repeated key with its last value
		want := map[string]any{}
		add := func(kvs []any) {
			for i := 0; i < len(kvs); i += 2 {
				k := kvs[i].(string)
				if slices.Contains(reservedKeys, k) {
					k = "raft-" + k
				}
				want[k] = kvs[i+1]
			}
		}

		l := newLogger("raft-node")
		for range hegel.Draw(ht, hegel.Integers(0, 2)) {
			kvs := drawKVs(ht, key, value)
			add(kvs)
			l = l.With(kvs...)
		}
		kvs := drawKVs(ht, key, value)
		add(kvs)

		lines := captureLogLines(ht, func() { l.Info("args", kvs...) })
		require.Len(ht, lines, 1)
		m := decodeLogLine(ht, lines[0])
		for _, k := range reservedKeys {
			delete(m, k)
		}
		assert.Equal(ht, want, m)
	})
}

func TestLoggerStringerValues(t *testing.T) {
	hegel.Test(t, func(ht *hegel.T) {
		var v, want any
		switch hegel.Draw(ht, hegel.Integers(0, 6)) {
		case 0:
			s := hegel.Draw(ht, hegel.Text())
			v, want = testStringer{s}, s
		case 1:
			v, want = (*testPtrStringer)(nil), "<nil>"
		case 2:
			st := raft.RaftState(hegel.Draw(ht, hegel.Integers[uint32](0, 4)))
			v, want = st, st.String()
		case 3:
			sf := raft.ServerSuffrage(hegel.Draw(ht, hegel.Integers(0, 3)))
			v, want = sf, sf.String()
		case 4:
			r := &raft.Raft{}
			v, want = r, r.String()
		case 5:
			ms := hegel.Draw(ht, hegel.Integers(-1000, 1000))
			v, want = time.Duration(ms)*time.Millisecond, float64(ms)
		case 6:
			ts := time.Unix(hegel.Draw(ht, hegel.Integers[int64](0, 1<<33)), 0).UTC()
			v, want = ts, ts.Format(time.RFC3339)
		}

		l := newLogger("raft-node")
		args := []any{"v", v}
		if hegel.Draw(ht, hegel.Booleans()) {
			l, args = l.With(args...), nil
		}
		lines := captureLogLines(ht, func() { l.Info("stringer", args...) })
		require.Len(ht, lines, 1)
		m := decodeLogLine(ht, lines[0])
		assert.Equal(ht, want, m["v"], "line: %s", lines[0])
	})
}

type testStringer struct{ s string }

func (s testStringer) String() string { return s.s }

type testPtrStringer struct{ s string }

func (s *testPtrStringer) String() string { return s.s }

// reservedKeys are the fields the logger writes itself.
var reservedKeys = []string{"time", "level", "message", "component"}

// loggerTestKeys are arg keys that collide with fields the logger writes
// or with their renamed forms.
var loggerTestKeys = append(slices.Clone(reservedKeys),
	"raft-time", "raft-level", "raft-message", "raft-component",
	hclog.MissingKey,
)

func asAny[T any](g hegel.Generator[T]) hegel.Generator[any] {
	return hegel.Map(g, func(v T) any { return v })
}

// drawKVs draws up to four key/value pairs.
func drawKVs(ht *hegel.T, key, value hegel.Generator[any]) []any {
	var kvs []any
	for range hegel.Draw(ht, hegel.Integers(0, 4)) {
		kvs = append(kvs, hegel.Draw(ht, key), hegel.Draw(ht, value))
	}
	return kvs
}

// decodeLogLine asserts that line is valid UTF-8 without duplicate keys and
// returns it decoded.
func decodeLogLine(t testing.TB, line []byte) map[string]any {
	t.Helper()

	assert.True(t, utf8.Valid(line), "line: %q", line)
	assert.Empty(t, duplicateKeys(t, line), "line: %s", line)
	var m map[string]any
	require.NoError(t, json.Unmarshal(line, &m), "line: %s", line)
	return m
}

func assertTimestamp(t testing.TB, m map[string]any) {
	t.Helper()

	ts, _ := m["time"].(string)
	_, err := time.Parse(time.RFC3339, ts)
	assert.NoError(t, err, "time must be the timestamp, got %v", m["time"])
}

// assertField asserts that m has key set to want, or no key when want is
// empty.
func assertField(t testing.TB, m map[string]any, key, want string) {
	t.Helper()

	if want == "" {
		assert.NotContains(t, m, key)
	} else {
		assert.Equal(t, want, m[key])
	}
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
