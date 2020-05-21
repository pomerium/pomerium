package trace

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"go.opencensus.io/plugin/ochttp/propagation/b3"
	"go.opencensus.io/trace"
	"google.golang.org/grpc/metadata"
)

func Test_GRPCServerTracingHandler(t *testing.T) {
	h := NewGRPCServerTracingHandler("test_service")

	t.Run("b3", func(t *testing.T) {

		traceID := "742babd53873d170"
		traceIDParsed, _ := b3.ParseTraceID(traceID)

		spanID := "596a86e14ae535cb"
		spanIDParsed, _ := b3.ParseSpanID(spanID)

		sampled := "1"
		sampledParsed, _ := b3.ParseSampled(sampled)

		ctx := metadata.NewIncomingContext(context.Background(),
			metadata.Pairs(
				"x-b3-traceid", traceID,
				"x-b3-spanid", spanID,
				"x-b3-sampled", sampled,
			),
		)

		spanContext := trace.FromContext(h.TagRPC(ctx, nil)).SpanContext()

		assert.NotEqual(t, spanContext.SpanID, spanIDParsed)
		assert.NotEmpty(t, spanContext.SpanID)
		assert.Equal(t, traceIDParsed, spanContext.TraceID)
		assert.Equal(t, spanContext.TraceOptions, sampledParsed)

	})

	t.Run("none", func(t *testing.T) {
		ctx := metadata.NewIncomingContext(context.Background(), metadata.New(nil))

		spanContext := trace.FromContext(h.TagRPC(ctx, nil)).SpanContext()
		assert.NotEmpty(t, spanContext.SpanID)
		assert.NotEmpty(t, spanContext.TraceID)
	})

}
