package healthv2

import (
	"slices"

	"github.com/pomerium/pomerium/pkg/health/v2/check"
)

type CheckerStatus struct {
	Group   check.Group
	Name    string
	Results []check.Result
}

func (c CheckerStatus) Equal(other CheckerStatus) bool {
	return c.Group == other.Group &&
		c.Name == other.Name &&
		slices.EqualFunc(c.Results, other.Results, check.Result.Equal)
}

// A Snapshot must not be modified.
type Snapshot struct {
	// FIXME: hack so an empty snapshot is not healthy.
	Configured  bool
	Terminating bool
	Checkers    []CheckerStatus
}

func (s Snapshot) Equal(other Snapshot) bool {
	return s.Configured == other.Configured &&
		s.Terminating == other.Terminating &&
		slices.EqualFunc(s.Checkers, other.Checkers, CheckerStatus.Equal)
}

func (s Snapshot) Started() bool {
	return s.AllResults(func(r check.Result) bool { return r.Status != check.StatusUnknown })
}

func (s Snapshot) Ready() bool {
	return s.AllResults(func(r check.Result) bool { return r.Status == check.StatusRunning && r.Err == nil })
}

func (s Snapshot) Live() bool {
	return s.AllResults(func(r check.Result) bool { return r.Status != check.StatusUnknown && r.Err == nil })
}

func (s Snapshot) Required() []string {
	var names []string
	for _, c := range s.Checkers {
		for _, r := range c.Results {
			names = append(names, string(r.Name))
		}
	}
	slices.Sort(names)
	return names
}

func (s Snapshot) AllResults(pred func(check.Result) bool) bool {
	if !s.Configured {
		return false
	}
	for _, c := range s.Checkers {
		for _, r := range c.Results {
			if !pred(r) {
				return false
			}
		}
	}
	return true
}

func (s Snapshot) AnyResult(pred func(check.Result) bool) bool {
	for _, c := range s.Checkers {
		if slices.ContainsFunc(c.Results, pred) {
			return true
		}
	}
	return false
}
