package idpsession

import (
	"context"
	"time"

	"github.com/google/btree"
)

type changeQueue struct {
	changeSets *btree.BTreeG[ChangeSet]
}

func NewChangeQueue() ChangeQueue {
	return &changeQueue{
		changeSets: btree.NewG(2, changeSetLess),
	}
}

func (q *changeQueue) Schedule(_ context.Context, changeSets ...ChangeSet) {
	for _, changeSet := range changeSets {
		q.changeSets.ReplaceOrInsert(changeSet)
	}
}

func (q *changeQueue) ProcessDue(at time.Time, process func([]ChangeSet) error) error {
	due := q.due(at)
	if len(due) == 0 {
		return nil
	}
	if err := process(due); err != nil {
		return err
	}
	q.remove(due)
	return nil
}

func (q *changeQueue) Reset() {
	q.changeSets.Clear(false)
}

func (q *changeQueue) due(at time.Time) []ChangeSet {
	due := make([]ChangeSet, 0)
	q.changeSets.DescendLessOrEqual(ChangeSet{At: at.Add(time.Nanosecond)}, func(changeSet ChangeSet) bool {
		due = append(due, changeSet)
		return true
	})
	return due
}

func (q *changeQueue) remove(changeSets []ChangeSet) {
	for _, changeSet := range changeSets {
		q.changeSets.Delete(changeSet)
	}
}
