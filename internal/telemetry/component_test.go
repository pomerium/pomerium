package telemetry_test

import (
	"bytes"
	"testing"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace/noop"

	"github.com/pomerium/pomerium/internal/telemetry"
)

func TestLogger(t *testing.T) {
	t.Parallel()
	t.Run("handles duplicate attributes", func(t *testing.T) {
		t.Parallel()
		var buf bytes.Buffer
		logger := zerolog.New(&buf)
		ctx := logger.WithContext(t.Context())
		component := telemetry.NewComponent(noop.NewTracerProvider(), zerolog.InfoLevel, "test-component",
			attribute.String("a", "1"), attribute.String("a", "2"))
		component.Logger(ctx, attribute.String("a", "3")).Info().Msg("test")
		assert.JSONEq(t, `{
			"level": "info",
			"component": "test-component",
			"message": "test",
			"a": "3"
		}`, buf.String())
	})
}
