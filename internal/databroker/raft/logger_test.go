package raft

import (
	"bufio"
	"bytes"
	"encoding/json"
	"testing"
	"time"

	"github.com/hashicorp/go-hclog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

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
func duplicateKeys(t *testing.T, line []byte) []string {
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
