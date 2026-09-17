package idpsession

import (
	"cmp"
	"slices"
	"time"
)

type idleTracker struct {
	deadlines map[string]time.Time
}

func NewIdleTracker() IdleTracker {
	return &idleTracker{deadlines: make(map[string]time.Time)}
}

func (t *idleTracker) ProcessDue(at time.Time, process func([]string) error) error {
	ids := make([]string, 0)
	due := make(map[string]time.Time)
	for id, deadline := range t.deadlines {
		if !deadline.After(at) {
			ids = append(ids, id)
			due[id] = deadline
		}
	}
	slices.SortFunc(ids, func(a, b string) int {
		if order := due[a].Compare(due[b]); order != 0 {
			return order
		}
		return cmp.Compare(a, b)
	})

	if len(ids) == 0 {
		return nil
	}
	if err := process(ids); err != nil {
		return err
	}

	for id, deadline := range due {
		if t.deadlines[id].Equal(deadline) {
			delete(t.deadlines, id)
		}
	}
	return nil
}

func (t *idleTracker) Set(id string, deadline time.Time) {
	if _, ok := t.deadlines[id]; ok {
		return
	}
	t.deadlines[id] = deadline
}

func (t *idleTracker) Clear(id string) {
	delete(t.deadlines, id)
}

func (t *idleTracker) Reset() {
	clear(t.deadlines)
}
