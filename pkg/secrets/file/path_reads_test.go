package file

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// These tests drive pathReads' state transitions directly, with a fixed clock
// and no goroutines: each call stands in for one Provider.update or acquire.

const testRetry = time.Second

var testEpoch = time.Unix(1_000_000, 0)

func newTestPathReads() *pathReads {
	return &pathReads{path: "/secret", parked: make(map[*readCall]struct{})}
}

// startRead admits a fetch at now that must start a fresh read.
func startRead(t *testing.T, pr *pathReads, now time.Time) *readCall {
	t.Helper()
	a, err := pr.admit(t.Context(), now, testRetry, false)
	require.NoError(t, err)
	require.NotNil(t, a.read, "admission must be a read")
	require.True(t, a.fresh, "admission must start a fresh read")
	require.Nil(t, a.probe)
	return a.read
}

// parkReads parks n reads on dev, one retry interval apart starting at now,
// and returns the time the last one started along with the reads.
func parkReads(t *testing.T, pr *pathReads, now time.Time, n int, dev uint64) (time.Time, []*readCall) {
	t.Helper()
	var parked []*readCall
	for i := range n {
		if i > 0 {
			now = now.Add(testRetry)
		}
		c := startRead(t, pr, now)
		c.dev, c.devKnown = dev, true
		pr.abandon(t.Context(), c)
		require.True(t, c.parked)
		parked = append(parked, c)
	}
	return now, parked
}

func TestPathReadsJoinsLiveRead(t *testing.T) {
	pr := newTestPathReads()
	c := startRead(t, pr, testEpoch)

	a, err := pr.admit(t.Context(), testEpoch, testRetry, false)
	require.NoError(t, err)
	assert.Same(t, c, a.read)
	assert.False(t, a.fresh, "a joined read must not be started again")
	assert.Equal(t, 2, c.waiters)
}

func TestPathReadsParksOnlyWhenLastWaiterLeaves(t *testing.T) {
	pr := newTestPathReads()
	c := startRead(t, pr, testEpoch)
	_, err := pr.admit(t.Context(), testEpoch, testRetry, false)
	require.NoError(t, err)

	pr.abandon(t.Context(), c)
	assert.Same(t, c, pr.live, "a read with a waiter left stays live")
	assert.False(t, c.parked)

	pr.abandon(t.Context(), c)
	assert.Nil(t, pr.live)
	assert.True(t, c.parked)
	assert.Contains(t, pr.parked, c)
	assert.False(t, pr.idle(), "a parked read must keep the path's state")
}

func TestPathReadsDoesNotParkFinishedRead(t *testing.T) {
	pr := newTestPathReads()
	c := startRead(t, pr, testEpoch)

	pr.finishRead(t.Context(), c, []byte("v"), nil)
	assert.Nil(t, pr.live, "a finished read must not be joined")
	pr.abandon(t.Context(), c)
	assert.False(t, c.parked)
	assert.Empty(t, pr.parked)
	assert.True(t, pr.idle())
}

func TestPathReadsDoesNotJoinParkedRead(t *testing.T) {
	pr := newTestPathReads()
	_, _ = parkReads(t, pr, testEpoch, 1, 1)

	c := startRead(t, pr, testEpoch.Add(testRetry))
	assert.NotContains(t, pr.parked, c)
}

func TestPathReadsSpacesRetriesWhileParked(t *testing.T) {
	pr := newTestPathReads()
	last, _ := parkReads(t, pr, testEpoch, 1, 1)

	_, err := pr.admit(t.Context(), last.Add(testRetry-time.Nanosecond), testRetry, false)
	assert.ErrorIs(t, err, ErrReadBlocked)
	startRead(t, pr, last.Add(testRetry))
}

func TestPathReadsParkedReadReturning(t *testing.T) {
	pr := newTestPathReads()
	now := testEpoch
	c := startRead(t, pr, now)
	pr.abandon(t.Context(), c)

	pr.finishRead(t.Context(), c, nil, nil)
	assert.Empty(t, pr.parked)
	assert.True(t, pr.idle())
	// With nothing parked, a fetch no longer waits out the retry interval.
	startRead(t, pr, now)
}

func TestPathReadsProbesAtParkedCap(t *testing.T) {
	pr := newTestPathReads()
	last, _ := parkReads(t, pr, testEpoch, MaxParkedReads, 1)
	now := last.Add(testRetry)

	a, err := pr.admit(t.Context(), now, testRetry, true)
	assert.ErrorIs(t, err, ErrReadBlocked, "a fetch that already probed must not ask again")
	assert.Nil(t, a.probe)

	a, err = pr.admit(t.Context(), now, testRetry, false)
	require.NoError(t, err)
	require.NotNil(t, a.probe)
	assert.Nil(t, a.read)
	assert.Same(t, a.probe, pr.probe)

	_, err = pr.admit(t.Context(), now, testRetry, false)
	assert.ErrorIs(t, err, ErrReadBlocked, "a fetch must not wait on another fetch's probe")
}

func TestPathReadsProbeAdmitsOneReadOnNewDevice(t *testing.T) {
	pr := newTestPathReads()
	last, _ := parkReads(t, pr, testEpoch, MaxParkedReads, 1)
	now := last.Add(testRetry)

	a, err := pr.admit(t.Context(), now, testRetry, false)
	require.NoError(t, err)
	pr.finishProbe(t.Context(), a.probe, fileState{exists: true, dev: 2}, now)
	assert.True(t, pr.admitReady)

	c := startRead(t, pr, now)
	assert.True(t, c.devKnown, "an admitted read is attributed to the probe's device")
	assert.Equal(t, uint64(2), c.dev)
	assert.False(t, pr.admitReady, "an admission is used once")

	// Parked on the new device too, the path is refused until another
	// remount: a probe finding device 2 again admits nothing.
	pr.abandon(t.Context(), c)
	now = now.Add(testRetry)
	a, err = pr.admit(t.Context(), now, testRetry, false)
	require.NoError(t, err)
	pr.finishProbe(t.Context(), a.probe, fileState{exists: true, dev: 2}, now)
	assert.False(t, pr.admitReady)
	_, err = pr.admit(t.Context(), now, testRetry, true)
	assert.ErrorIs(t, err, ErrReadBlocked)
}

func TestPathReadsProbeAdmitsNothing(t *testing.T) {
	for _, tc := range []struct {
		name string
		st   fileState
	}{
		{"same device", fileState{exists: true, dev: 1}},
		{"missing path", fileState{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pr := newTestPathReads()
			last, _ := parkReads(t, pr, testEpoch, MaxParkedReads, 1)
			now := last.Add(testRetry)

			a, err := pr.admit(t.Context(), now, testRetry, false)
			require.NoError(t, err)
			pr.finishProbe(t.Context(), a.probe, tc.st, now)
			assert.False(t, pr.admitReady)
			assert.Nil(t, pr.probe)
			_, err = pr.admit(t.Context(), now, testRetry, true)
			assert.ErrorIs(t, err, ErrReadBlocked)
		})
	}
}

func TestPathReadsSpacesProbes(t *testing.T) {
	pr := newTestPathReads()
	last, _ := parkReads(t, pr, testEpoch, MaxParkedReads, 1)
	now := last.Add(testRetry)

	pc := pr.startProbe(t.Context(), now, testRetry)
	require.NotNil(t, pc)
	pr.finishProbe(t.Context(), pc, fileState{exists: true, dev: 1}, now)

	assert.Nil(t, pr.startProbe(t.Context(), now.Add(testRetry-time.Nanosecond), testRetry))
	assert.NotNil(t, pr.startProbe(t.Context(), now.Add(testRetry), testRetry))
}

func TestPathReadsReplacesStuckProbeWithBackoff(t *testing.T) {
	pr := newTestPathReads()
	last, _ := parkReads(t, pr, testEpoch, MaxParkedReads, 1)
	now := last.Add(testRetry)

	first := pr.startProbe(t.Context(), now, testRetry)
	require.NotNil(t, first)
	assert.Nil(t, pr.startProbe(t.Context(), now.Add(testRetry-time.Nanosecond), testRetry),
		"a probe within its backoff is not presumed stuck")

	now = now.Add(testRetry)
	second := pr.startProbe(t.Context(), now, testRetry)
	require.NotNil(t, second)
	assert.True(t, first.abandoned)
	assert.Same(t, second, pr.probe)
	assert.Equal(t, 1, pr.probesParked)
	assert.Equal(t, 2*testRetry, pr.probeBackoff)
	assert.Nil(t, pr.startProbe(t.Context(), now.Add(2*testRetry-time.Nanosecond), testRetry),
		"the backoff doubles for the replacement")

	// The stuck probe returning neither unlinks its replacement nor resets
	// the backoff, but its verdict still counts.
	pr.finishProbe(t.Context(), first, fileState{exists: true, dev: 2}, now)
	assert.Zero(t, pr.probesParked)
	assert.Same(t, second, pr.probe)
	assert.Equal(t, 2*testRetry, pr.probeBackoff)
	assert.True(t, pr.admitReady)

	pr.finishProbe(t.Context(), second, fileState{exists: true, dev: 1}, now)
	assert.Nil(t, pr.probe)
	assert.Zero(t, pr.probeBackoff, "a returned probe resets the backoff")
}

func TestPathReadsBoundsParkedProbes(t *testing.T) {
	pr := newTestPathReads()
	last, _ := parkReads(t, pr, testEpoch, MaxParkedReads, 1)
	now := last.Add(testRetry)

	require.NotNil(t, pr.startProbe(t.Context(), now, testRetry))
	for pr.probesParked+1 < MaxParkedProbes {
		now = now.Add(maxProbeBackoff)
		require.NotNil(t, pr.startProbe(t.Context(), now, testRetry))
	}
	assert.Equal(t, MaxParkedProbes-1, pr.probesParked, "the in-flight probe counts toward the cap")
	assert.Equal(t, maxProbeBackoff, pr.probeBackoff, "the backoff is capped")
	assert.Nil(t, pr.startProbe(t.Context(), now.Add(maxProbeBackoff), testRetry))
}

func TestPathReadsAdmissionLapsesWithParkedReads(t *testing.T) {
	pr := newTestPathReads()
	last, parked := parkReads(t, pr, testEpoch, MaxParkedReads, 1)
	now := last.Add(testRetry)
	a, err := pr.admit(t.Context(), now, testRetry, false)
	require.NoError(t, err)
	pr.finishProbe(t.Context(), a.probe, fileState{exists: true, dev: 2}, now)
	require.True(t, pr.admitReady)

	for _, c := range parked {
		pr.finishRead(t.Context(), c, nil, nil)
	}
	assert.False(t, pr.admitReady)
	assert.True(t, pr.idle(), "with no reads parked, nothing is worth keeping")
}

func TestPathReadsProbeAfterParkedReadsDrainAdmitsNothing(t *testing.T) {
	pr := newTestPathReads()
	last, parked := parkReads(t, pr, testEpoch, MaxParkedReads, 1)
	now := last.Add(testRetry)
	a, err := pr.admit(t.Context(), now, testRetry, false)
	require.NoError(t, err)
	for _, c := range parked {
		pr.finishRead(t.Context(), c, nil, nil)
	}

	pr.finishProbe(t.Context(), a.probe, fileState{exists: true, dev: 2}, now)
	assert.False(t, pr.admitReady)
	assert.True(t, pr.idle())
}

// A read started below the cap after an admission was granted can park on the
// admitted device itself; the admission must not then let a second read onto
// it without a fresh probe.
func TestPathReadsAdmissionVoidedByReadParkedOnItsDevice(t *testing.T) {
	pr := newTestPathReads()
	last, parked := parkReads(t, pr, testEpoch, MaxParkedReads, 1)
	now := last.Add(testRetry)
	a, err := pr.admit(t.Context(), now, testRetry, false)
	require.NoError(t, err)
	pr.finishProbe(t.Context(), a.probe, fileState{exists: true, dev: 2}, now)
	require.True(t, pr.admitReady)

	// One parked read returns, so the path drops below the cap and a retry
	// starts a read that opens on device 2 and parks there.
	pr.finishRead(t.Context(), parked[0], nil, nil)
	c := startRead(t, pr, now)
	c.dev, c.devKnown = 2, true
	pr.abandon(t.Context(), c)
	require.Len(t, pr.parked, MaxParkedReads)

	a, err = pr.admit(t.Context(), now, testRetry, true)
	assert.ErrorIs(t, err, ErrReadBlocked)
	assert.Nil(t, a.read)
	assert.False(t, pr.admitReady)
}

func TestPathReadsParkedReadReturningLeavesLiveRead(t *testing.T) {
	pr := newTestPathReads()
	last, parked := parkReads(t, pr, testEpoch, 1, 1)
	old := parked[0]
	live := startRead(t, pr, last.Add(testRetry))

	pr.finishRead(t.Context(), old, nil, nil)
	assert.Same(t, live, pr.live)
	assert.Empty(t, pr.parked)
}

func TestProviderUpdateKeepsNewerPathReads(t *testing.T) {
	p := New()
	stale := newTestPathReads()
	current := newTestPathReads()
	current.live = &readCall{done: make(chan struct{}), waiters: 1}
	p.reads = map[string]*pathReads{current.path: current}

	p.update(stale, func() {})
	assert.Same(t, current, p.reads[current.path], "a retired pathReads must not drop its successor")

	current.live = nil
	p.update(current, func() {})
	assert.NotContains(t, p.reads, current.path)
}
