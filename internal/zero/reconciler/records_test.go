package reconciler_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/pomerium/pomerium/internal/zero/reconciler"
)

type testRecord struct {
	Type string
	ID   string
	Val  string
}

func (r testRecord) GetID() string {
	return r.ID
}

func (r testRecord) GetType() string {
	return r.Type
}

func (r testRecord) Equal(other testRecord) bool {
	return r.ID == other.ID && r.Type == other.Type && r.Val == other.Val
}

func TestRecords(t *testing.T) {
	initial := make(reconciler.RecordSetBundle[testRecord])
	initial.Add(testRecord{ID: "1", Type: "a", Val: "a-1"})
	initial.Add(testRecord{ID: "2", Type: "a", Val: "a-2"})
	initial.Add(testRecord{ID: "1", Type: "b", Val: "b-1"})

	// test record types
	assert.ElementsMatch(t, []string{"a", "b"}, initial.RecordTypes())

	// test added, deleted and modified
	updated := make(reconciler.RecordSetBundle[testRecord])
	updated.Add(testRecord{ID: "1", Type: "a", Val: "a-1-1"})
	updated.Add(testRecord{ID: "3", Type: "a", Val: "a-3"})
	updated.Add(testRecord{ID: "1", Type: "b", Val: "b-1"})
	updated.Add(testRecord{ID: "2", Type: "b", Val: "b-2"})
	updated.Add(testRecord{ID: "1", Type: "c", Val: "c-1"})

	assert.ElementsMatch(t, []string{"a", "b", "c"}, updated.RecordTypes())

	added := initial.GetAdded(updated)
	assert.Equal(t,
		reconciler.RecordSetBundle[testRecord]{
			"a": reconciler.RecordSet[testRecord]{
				"3": {ID: "3", Type: "a", Val: "a-3"},
			},
			"b": reconciler.RecordSet[testRecord]{
				"2": {ID: "2", Type: "b", Val: "b-2"},
			},
			"c": reconciler.RecordSet[testRecord]{
				"1": {ID: "1", Type: "c", Val: "c-1"},
			},
		}, added)

	removed := initial.GetRemoved(updated)
	assert.Equal(t,
		reconciler.RecordSetBundle[testRecord]{
			"a": reconciler.RecordSet[testRecord]{
				"2": {ID: "2", Type: "a", Val: "a-2"},
			},
		}, removed)

	modified := initial.GetModified(updated)
	assert.Equal(t,
		reconciler.RecordSetBundle[testRecord]{
			"a": reconciler.RecordSet[testRecord]{
				"1": {ID: "1", Type: "a", Val: "a-1-1"},
			},
		}, modified)
}
