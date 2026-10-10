package file

import (
	"math/rand/v2"
	"slices"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// These tests drive the fetch state machine without goroutines or the
// filesystem: pathReads' transitions directly, with a fixed clock, and
// readGroup's methods, which read the real one.

const testRetry = time.Second

var testEpoch = time.Unix(1_000_000, 0)

func isClosed(ch <-chan struct{}) bool {
	select {
	case <-ch:
		return true
	default:
		return false
	}
}

func newTestPathReads() *pathReads {
	return &pathReads{path: "/secret", parked: make(map[*readCall]struct{})}
}

// startRead admits a fetch at now that must start a fresh read.
func startRead(t *testing.T, pr *pathReads, now time.Time) *readCall {
	t.Helper()
	c, fresh, err := pr.admit(t.Context(), now, testRetry)
	require.NoError(t, err)
	require.NotNil(t, c)
	require.True(t, fresh, "admission must start a fresh read")
	return c
}

// parkReads parks n reads, one retry interval apart starting at now, and
// returns the time the last one started along with the reads.
func parkReads(t *testing.T, pr *pathReads, now time.Time, n int) (time.Time, []*readCall) {
	t.Helper()
	var parked []*readCall
	for i := range n {
		if i > 0 {
			now = now.Add(testRetry)
		}
		c := startRead(t, pr, now)
		pr.abandon(t.Context(), c, testEpoch)
		require.Contains(t, pr.parked, c)
		parked = append(parked, c)
	}
	return now, parked
}

func TestPathReadsJoinsLiveRead(t *testing.T) {
	pr := newTestPathReads()
	c := startRead(t, pr, testEpoch)

	joined, fresh, err := pr.admit(t.Context(), testEpoch, testRetry)
	require.NoError(t, err)
	assert.Same(t, c, joined)
	assert.False(t, fresh, "a joined read must not be started again")
	assert.Equal(t, 2, c.waiters)
}

func TestPathReadsParksOnlyWhenLastWaiterLeaves(t *testing.T) {
	pr := newTestPathReads()
	c := startRead(t, pr, testEpoch)
	_, _, err := pr.admit(t.Context(), testEpoch, testRetry)
	require.NoError(t, err)

	pr.abandon(t.Context(), c, testEpoch)
	assert.Same(t, c, pr.live, "a read with a waiter left stays live")
	assert.NotContains(t, pr.parked, c)

	pr.abandon(t.Context(), c, testEpoch)
	assert.Nil(t, pr.live)
	assert.Contains(t, pr.parked, c)
	assert.False(t, pr.idle(), "a parked read must keep the path's state")
}

func TestPathReadsDoesNotParkFinishedRead(t *testing.T) {
	pr := newTestPathReads()
	c := startRead(t, pr, testEpoch)

	pr.finishRead(t.Context(), c, []byte("v"), nil, testEpoch)
	assert.Nil(t, pr.live, "a finished read must not be joined")
	assert.True(t, isClosed(c.done), "finishing a read publishes it")
	pr.abandon(t.Context(), c, testEpoch)
	assert.Empty(t, pr.parked)
	assert.True(t, pr.idle())
}

func TestPathReadsDoesNotJoinParkedRead(t *testing.T) {
	pr := newTestPathReads()
	_, _ = parkReads(t, pr, testEpoch, 1)

	c := startRead(t, pr, testEpoch.Add(testRetry))
	assert.NotContains(t, pr.parked, c)
}

func TestPathReadsSpacesRetriesWhileParked(t *testing.T) {
	pr := newTestPathReads()
	last, _ := parkReads(t, pr, testEpoch, 1)

	_, _, err := pr.admit(t.Context(), last.Add(testRetry-time.Nanosecond), testRetry)
	assert.ErrorIs(t, err, ErrReadBlocked)
	startRead(t, pr, last.Add(testRetry))
}

func TestPathReadsParkedReadReturning(t *testing.T) {
	pr := newTestPathReads()
	now := testEpoch
	c := startRead(t, pr, now)
	pr.abandon(t.Context(), c, testEpoch)

	pr.finishRead(t.Context(), c, nil, nil, testEpoch)
	assert.Empty(t, pr.parked)
	assert.True(t, pr.idle())
	// With nothing parked, a fetch no longer waits out the retry interval.
	startRead(t, pr, now)
}

func TestPathReadsRefusesAtParkedCap(t *testing.T) {
	pr := newTestPathReads()
	last, parked := parkReads(t, pr, testEpoch, MaxParkedReads)

	// However long a fetch waits, the cap refuses it without recording anything.
	for _, d := range []time.Duration{testRetry, time.Hour, 24 * time.Hour} {
		c, _, err := pr.admit(t.Context(), last.Add(d), testRetry)
		assert.ErrorIs(t, err, ErrReadBlocked)
		assert.Nil(t, c)
	}
	assert.Nil(t, pr.live)
	assert.Len(t, pr.parked, MaxParkedReads)

	// One parked read returning makes room for one fresh read.
	pr.finishRead(t.Context(), parked[0], nil, nil, testEpoch)
	startRead(t, pr, last.Add(testRetry))
}

func TestPathReadsParkedReadReturningLeavesLiveRead(t *testing.T) {
	pr := newTestPathReads()
	last, parked := parkReads(t, pr, testEpoch, 1)
	old := parked[0]
	live := startRead(t, pr, last.Add(testRetry))

	pr.finishRead(t.Context(), old, nil, nil, testEpoch)
	assert.Same(t, live, pr.live)
	assert.Empty(t, pr.parked)
}

// A caller whose ctx ends just as its read finishes releases the read after
// its pathReads may have been retired and the path taken by a newer one; that
// must leave the newer one alone.
func TestReadGroupLateAbandonKeepsNewerPathReads(t *testing.T) {
	var g readGroup
	stale, _, err := g.admit(t.Context(), "/secret", testRetry)
	require.NoError(t, err)
	g.finishRead(t.Context(), stale, []byte("v"), nil)
	require.NotContains(t, g.paths, "/secret", "an idle pathReads is retired")

	fresh, _, err := g.admit(t.Context(), "/secret", testRetry)
	require.NoError(t, err)
	current := g.paths["/secret"]
	require.NotSame(t, stale.owner, current)

	g.abandon(t.Context(), stale)
	assert.Same(t, current, g.paths["/secret"])
	assert.Same(t, fresh, current.live)
}

// TestReadGroupInvariants drives a readGroup through random interleavings of
// what fetches and their reads do, and checks after every step the invariants
// the lock-free fetch code relies on.
func TestReadGroupInvariants(t *testing.T) {
	ctx := zerolog.Nop().WithContext(t.Context())
	paths := []string{"/a", "/b"}
	for seed := range uint64(500) {
		rng := rand.New(rand.NewPCG(seed, 0))
		retry := time.Duration(rng.IntN(2)) * time.Microsecond
		var g readGroup
		var (
			waiters []*readCall // one per caller waiting on a read
			reads   []*readCall // started and not yet returned
		)
		pick := func(n int) int { return rng.IntN(n) }
		for range 200 {
			switch rng.IntN(4) {
			case 0: // a fetch arrives
				c, fresh, err := g.admit(ctx, paths[pick(len(paths))], retry)
				if err != nil {
					require.ErrorIs(t, err, ErrReadBlocked)
					break
				}
				if fresh {
					reads = append(reads, c)
				}
				waiters = append(waiters, c)
			case 1: // a caller gives up, perhaps just as its read finished
				if len(waiters) > 0 {
					i := pick(len(waiters))
					g.abandon(ctx, waiters[i])
					waiters = slices.Delete(waiters, i, i+1)
				}
			case 2: // a caller sees its read finish
				if len(waiters) > 0 {
					if i := pick(len(waiters)); isClosed(waiters[i].done) {
						waiters = slices.Delete(waiters, i, i+1)
					}
				}
			case 3: // a read returns
				if len(reads) > 0 {
					i := pick(len(reads))
					g.finishRead(ctx, reads[i], nil, nil)
					reads = slices.Delete(reads, i, i+1)
				}
			}
			checkReadGroup(t, &g, reads)
		}
	}
}

func checkReadGroup(t *testing.T, g *readGroup, reads []*readCall) {
	t.Helper()
	for path, pr := range g.paths {
		require.Equal(t, path, pr.path)
		require.False(t, pr.idle(), "an idle pathReads was left in paths")
		require.LessOrEqual(t, len(pr.parked), MaxParkedReads, "a path parked more reads than the cap")
	}
	for _, c := range reads {
		require.Same(t, g.paths[c.owner.path], c.owner, "a running read's owner is not the one in paths")
		_, parked := c.owner.parked[c]
		require.NotEqual(t, parked, c.owner.live == c, "a running read must be exactly one of live or parked")
		require.False(t, isClosed(c.done))
	}
}
