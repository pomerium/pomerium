package resolver

import (
	"fmt"
	"time"

	"github.com/pomerium/pomerium/pkg/secrets/provider"
	"github.com/pomerium/pomerium/pkg/secrets/ref"
)

// State is the externally-visible cache state of a resolved value.
type State int

const (
	// StateFailed is the zero value: no successful fetch has ever completed.
	StateFailed State = iota
	// StateFresh means the last fetch succeeded within the refresh window.
	StateFresh
	// StateStale means refresh is failing but the last-good value is still
	// within its stale grace window.
	StateStale
	// StateExpired means the grace window elapsed without success; the value
	// has been dropped.
	StateExpired
)

// String returns a stable, value-free label for metrics and logs.
func (s State) String() string {
	switch s {
	case StateFresh:
		return "fresh"
	case StateStale:
		return "stale"
	case StateExpired:
		return "expired"
	default:
		return "failed"
	}
}

// LookupResult is what a View returns for a binding ID.
type LookupResult struct {
	Value string
	State State
	Found bool // binding ID known to the current snapshot
}

// secretBytes and secretString wrap secret material so that %v/%+v/%#v never
// print it. The real value is recovered only via explicit conversion (string()
// / []byte()) on the read path.
type secretBytes []byte

func (secretBytes) String() string   { return "[REDACTED]" }
func (secretBytes) GoString() string { return "[REDACTED]" }

type secretString string

func (secretString) String() string   { return "[REDACTED]" }
func (secretString) GoString() string { return "[REDACTED]" }

// snapshot is the immutable, atomically-published read model. Readers touch
// only this via one atomic pointer load plus two map reads.
type snapshot struct {
	bindings map[string]bindingInfo // binding ID -> value identity + metadata
	values   map[string]valueEntry  // valueKey (ref.Key()) -> value + state
}

type bindingInfo struct {
	valueKey    string
	metricLabel string
	scheme      string
}

type valueEntry struct {
	value secretString
	state State
}

// String/GoString redact valueEntry so a whole-struct %+v/%#v never prints the
// value. (fmt cannot invoke a Stringer on an unexported field, so redaction
// must live on the container types, not only on secretString.)
func (v valueEntry) String() string   { return fmt.Sprintf("valueEntry{state:%s}", v.state) }
func (v valueEntry) GoString() string { return v.String() }

// Lookup implements View.
func (s *snapshot) Lookup(id string) LookupResult {
	bi, ok := s.bindings[id]
	if !ok {
		return LookupResult{}
	}
	ve, ok := s.values[bi.valueKey]
	if !ok {
		return LookupResult{Found: true, State: StateFailed}
	}
	return LookupResult{Found: true, Value: string(ve.value), State: ve.state}
}

// valueState is the writer-side authoritative state for one valueKey. It is
// guarded by Resolver.mu.
type valueState struct {
	ref         ref.Ref
	valueKey    string
	staleGrace  time.Duration
	metricLabel string

	value        secretBytes
	state        State
	lastGood     time.Time
	loggedFirst  bool
	lastErrClass string
}

// String/GoString redact valueState (it holds the post-selector value).
func (vs *valueState) String() string {
	return fmt.Sprintf("valueState{label:%q key:%q state:%s}", vs.metricLabel, vs.valueKey, vs.state)
}
func (vs *valueState) GoString() string { return vs.String() }

// fetchState is the writer-side per-FetchKey bookkeeping. It is guarded by
// Resolver.mu except for the runtime channels/cancel which are set once.
type fetchState struct {
	fetchKey    string
	fetchRef    ref.Ref // representative ref (URL to fetch)
	provider    provider.Provider
	schemeLabel string

	refresh     time.Duration // min across bindings sharing this FetchKey
	negativeTTL time.Duration // min across bindings sharing this FetchKey

	values map[string]*valueState // valueKey -> state

	negativeUntil  time.Time
	negLoggedAt    time.Time
	lastVersion    string
	haveVersion    bool
	lastRawPayload secretBytes
	haveRawGood    bool

	cancel    func()
	watchStop func()
	notifyCh  chan struct{}
}

// String/GoString redact fetchState (it holds the last raw payload).
func (fs *fetchState) String() string {
	return fmt.Sprintf("fetchState{fetchKey:%q values:%d haveRawGood:%t}", fs.fetchKey, len(fs.values), fs.haveRawGood)
}
func (fs *fetchState) GoString() string { return fs.String() }

// backoffState is a loop-local exponential backoff, floored at minInterval and
// capped at maxBackoff.
type backoffState struct {
	cur time.Duration
}

const maxBackoff = 30 * time.Second

func (b *backoffState) reset() { b.cur = 0 }

func (b *backoffState) next() time.Duration {
	if b.cur == 0 {
		b.cur = minInterval
	} else {
		b.cur *= 2
	}
	b.cur = min(b.cur, maxBackoff)
	return b.cur
}

func errClass(err error) string {
	switch {
	case err == nil:
		return ""
	case provider.IsNotFound(err):
		return "not_found"
	default:
		return "transient"
	}
}
