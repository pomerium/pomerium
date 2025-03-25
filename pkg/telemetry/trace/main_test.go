package trace_test

import (
	"os"
	"testing"

	"github.com/pomerium/pomerium/pkg/telemetry/trace"
)

func TestMain(m *testing.M) {
	trace.UseGlobalPanicTracer()
	os.Exit(m.Run())
}
