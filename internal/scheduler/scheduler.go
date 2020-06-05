package scheduler

import (
	"strings"
	"time"

	"github.com/google/btree"
)

var maxTime = time.Unix(1<<63-62135596801, 999999999)

type item struct {
	time time.Time
	key  string
}

type itemByKey item

func (i itemByKey) Less(than btree.Item) bool {
	return strings.Compare(i.key, than.(itemByKey).key) < 0
}

type itemByTime item

func (i itemByTime) Less(than btree.Item) bool {
	xTime, yTime := i.time, than.(itemByTime).time
	switch {
	case xTime.Before(yTime):
		return true
	case yTime.Before(xTime):
		return false
	}

	return itemByKey(i).Less(itemByKey(than.(itemByTime)))
}

// A Scheduler implements a priority queue based on time. The scheduler is not thread-safe for multiple writers.
type Scheduler struct {
	byTime *btree.BTree
	byKey  *btree.BTree
}

// New creates a new Scheduler.
func New() *Scheduler {
	return &Scheduler{
		byTime: btree.New(8),
		byKey:  btree.New(8),
	}
}

// Add adds an item to the scheduler.
func (s *Scheduler) Add(due time.Time, key string) {
	i := s.byKey.Get(itemByKey{key: key})
	if i != nil {
		s.byTime.Delete(itemByTime(i.(itemByKey)))
	}
	s.byKey.ReplaceOrInsert(itemByKey{
		time: due,
		key:  key,
	})
	s.byTime.ReplaceOrInsert(itemByTime{
		time: due,
		key:  key,
	})
}

// Remove removes an item from the scheduler and de-schedules it.
func (s *Scheduler) Remove(key string) {
	i := s.byKey.Get(itemByKey{key: key})
	if i != nil {
		s.byKey.Delete(i)
		s.byTime.Delete(itemByTime(i.(itemByKey)))
	}
}

// Next retrieves the next time an item is due.
func (s *Scheduler) Next() (time.Time, string) {
	if s.byTime.Len() == 0 {
		return maxTime, ""
	}
	item := s.byTime.Min().(itemByTime)
	return item.time, item.key
}
