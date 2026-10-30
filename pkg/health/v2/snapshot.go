package healthv2

import (
	"maps"
	"slices"
)

type State int

const (
	StateStarting State = iota
	StateNotReady
	StateOK
	StateUnhealthy
)

func (s State) String() string {
	switch s {
	case StateNotReady:
		return "NOT_READY"
	case StateOK:
		return "OK"
	case StateUnhealthy:
		return "UNHEALTHY"
	default:
		return "STARTING"
	}
}

type Condition struct {
	OK   bool
	Info Info
}

func (c Condition) Equal(other Condition) bool {
	return c.OK == other.OK &&
		c.Info.Reason == other.Info.Reason &&
		maps.Equal(c.Info.Details, other.Info.Details)
}

type CheckerStatus struct {
	Service     ServiceID
	Name        string
	Initialized Condition
	Ready       Condition
	Healthy     Condition
}

func (c CheckerStatus) Key() string {
	return string(c.Service) + "/" + c.Name
}

// State returns Unhealthy, Starting, NotReady or OK, in that precedence.
func (c CheckerStatus) State() State {
	switch {
	case !c.Healthy.OK:
		return StateUnhealthy
	case !c.Initialized.OK:
		return StateStarting
	case !c.Ready.OK:
		return StateNotReady
	default:
		return StateOK
	}
}

// Reason returns the Reason of the first false condition, in the precedence
// of State.
func (c CheckerStatus) Reason() (string, bool) {
	switch {
	case !c.Healthy.OK:
		return c.Healthy.Info.Reason, true
	case !c.Initialized.OK:
		return c.Initialized.Info.Reason, true
	case !c.Ready.OK:
		return c.Ready.Info.Reason, true
	default:
		return "", false
	}
}

func (c CheckerStatus) Equal(other CheckerStatus) bool {
	return c.Service == other.Service &&
		c.Name == other.Name &&
		c.Initialized.Equal(other.Initialized) &&
		c.Ready.Equal(other.Ready) &&
		c.Healthy.Equal(other.Healthy)
}

// A Snapshot must not be modified. A Snapshot without checkers is the state
// before the first poll and is not initialized, ready or healthy.
type Snapshot struct {
	Checkers []CheckerStatus
}

func (s Snapshot) Equal(other Snapshot) bool {
	return slices.EqualFunc(s.Checkers, other.Checkers, CheckerStatus.Equal)
}

func (s Snapshot) Initialized() bool {
	return s.all(func(c CheckerStatus) Condition { return c.Initialized })
}

func (s Snapshot) Ready() bool {
	return s.all(func(c CheckerStatus) Condition { return c.Ready })
}

func (s Snapshot) Healthy() bool {
	return s.all(func(c CheckerStatus) Condition { return c.Healthy })
}

func (s Snapshot) all(cond func(CheckerStatus) Condition) bool {
	return len(s.Checkers) > 0 && !slices.ContainsFunc(s.Checkers, func(c CheckerStatus) bool { return !cond(c).OK })
}

func (s Snapshot) Keys() []string {
	var keys []string
	for _, c := range s.Checkers {
		keys = append(keys, c.Key())
	}
	slices.Sort(keys)
	return keys
}
