package databroker_test

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"google.golang.org/protobuf/proto"

	"github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/protoutil"
)

func TestRecords(t *testing.T) {
	t.Parallel()

	tr := func(id, typ, val string) *databroker.Record {
		return &databroker.Record{
			Id:   id,
			Type: typ,
			Data: protoutil.NewAnyString(val),
		}
	}

	cmpFn := func(a, b *databroker.Record) bool {
		return proto.Equal(a, b)
	}

	initial := make(databroker.RecordSetBundle)
	initial.Add(tr("1", "a", "a-1"))
	initial.Add(tr("2", "a", "a-2"))
	initial.Add(tr("1", "b", "b-1"))

	// test record types
	assert.ElementsMatch(t, []string{"a", "b"}, initial.RecordTypes())

	// test added, deleted and modified
	updated := make(databroker.RecordSetBundle)
	updated.Add(tr("1", "a", "a-1-1"))
	updated.Add(tr("3", "a", "a-3"))
	updated.Add(tr("1", "b", "b-1"))
	updated.Add(tr("2", "b", "b-2"))
	updated.Add(tr("1", "c", "c-1"))

	assert.ElementsMatch(t, []string{"a", "b", "c"}, updated.RecordTypes())

	equalJSON := func(a, b databroker.RecordSetBundle) {
		t.Helper()
		var txt [2]string
		for i, x := range [2]databroker.RecordSetBundle{a, b} {
			data, err := json.Marshal(x)
			assert.NoError(t, err)
			txt[i] = string(data)
		}
		assert.JSONEq(t, txt[0], txt[1])
	}

	added := initial.GetAdded(updated)
	equalJSON(added, databroker.RecordSetBundle{
		"a": databroker.RecordSet{
			"3": tr("3", "a", "a-3"),
		},
		"b": databroker.RecordSet{
			"2": tr("2", "b", "b-2"),
		},
		"c": databroker.RecordSet{
			"1": tr("1", "c", "c-1"),
		},
	})

	removed := initial.GetRemoved(updated)
	equalJSON(removed, databroker.RecordSetBundle{
		"a": databroker.RecordSet{
			"2": tr("2", "a", "a-2"),
		},
	})

	modified := initial.GetModified(updated, cmpFn)
	equalJSON(modified, databroker.RecordSetBundle{
		"a": databroker.RecordSet{
			"1": tr("1", "a", "a-1-1"),
		},
	})
}
