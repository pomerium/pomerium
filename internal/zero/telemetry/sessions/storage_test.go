package sessions_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/pomerium/pomerium/internal/zero/telemetry/sessions"
)

func TestStorage(t *testing.T) {
	t.Parallel()

	now := time.Date(2020, 1, 2, 3, 4, 5, 6, time.UTC)
	state := &sessions.MetricState{
		Data:      []byte("data"),
		LastReset: now,
	}

	pbany := state.ToAny()
	assert.NotNil(t, pbany)

	var newState sessions.MetricState
	err := newState.FromAny(pbany)
	assert.NoError(t, err)
	assert.EqualValues(t, state.Data, newState.Data)
	assert.EqualValues(t, state.LastReset.Truncate(time.Second), newState.LastReset.Truncate(time.Second))
}
