package file_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/trace/noop"

	"github.com/pomerium/pomerium/pkg/storage/file"
)

func TestBackendHealth(t *testing.T) {
	t.Parallel()

	backend := file.New(noop.NewTracerProvider(), "memory://")
	ready, info := backend.Ready(t.Context())
	assert.True(t, ready)
	assert.Equal(t, "memory", info.Details["storage"])
	healthy, _ := backend.Healthy(t.Context())
	assert.True(t, healthy)

	require.NoError(t, backend.Close())
	ready, info = backend.Ready(t.Context())
	assert.False(t, ready)
	assert.Equal(t, "backend closed", info.Reason)
	healthy, _ = backend.Healthy(t.Context())
	assert.False(t, healthy)
}
