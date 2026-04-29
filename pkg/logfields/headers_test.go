package logfields_test

import (
	"bytes"
	"strings"
	"testing"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"

	"github.com/pomerium/pomerium/pkg/logfields"
)

func TestHTTPHeaders(t *testing.T) {
	t.Parallel()

	type A = []string
	type M = map[string]string

	t.Run("all", func(t *testing.T) {
		t.Parallel()

		var buf bytes.Buffer
		log := zerolog.New(&buf)
		evt := log.Info()
		evt = logfields.HTTPHeaders(evt, A{"headers"}, M{
			"a": "1",
			"b": "2",
			"c": "3",
		})
		evt.Send()

		assert.Equal(t, `{"level":"info","headers":{"A":"1","B":"2","C":"3"}}`, strings.TrimSpace(buf.String()))
	})
	t.Run("none", func(t *testing.T) {
		t.Parallel()

		var buf bytes.Buffer
		log := zerolog.New(&buf)
		evt := log.Info()
		evt = logfields.HTTPHeaders(evt, A{"a", "b", "c"}, M{
			"a": "1",
			"b": "2",
			"c": "3",
		})
		evt.Send()

		assert.Equal(t, `{"level":"info"}`, strings.TrimSpace(buf.String()))
	})
	t.Run("two", func(t *testing.T) {
		t.Parallel()

		var buf bytes.Buffer
		log := zerolog.New(&buf)
		evt := log.Info()
		evt = logfields.HTTPHeaders(evt, A{"headers.a", "headers.C"}, M{
			"a": "1",
			"b": "2",
			"c": "3",
		})
		evt.Send()

		assert.Equal(t, `{"level":"info","headers":{"A":"1","C":"3"}}`, strings.TrimSpace(buf.String()))
	})
}
