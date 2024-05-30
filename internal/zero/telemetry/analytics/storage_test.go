package analytics_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/pomerium/pomerium/internal/zero/telemetry/analytics"
)

func TestStorage(t *testing.T) {
	t.Parallel()

	now := time.Date(2020, 1, 2, 3, 4, 5, 6, time.UTC)
	state := &analytics.MetricState{
		Data:      []byte("data"),
		LastReset: now,
	}

	pbany := state.ToAny()
	assert.NotNil(t, pbany)

	var newState analytics.MetricState
	err := newState.FromAny(pbany)
	assert.NoError(t, err)
	assert.EqualValues(t, state.Data, newState.Data)
	assert.EqualValues(t, state.LastReset.Truncate(time.Second), newState.LastReset.Truncate(time.Second))
}
