package inmemory

import (
	"container/list"

	"github.com/pomerium/pomerium/pkg/grpc/databroker"
)

type recordCollectionNode struct {
	*databroker.Record
	insertionOrderPtr *list.Element
}

// A RecordCollection is a collection of records which supports lookup by (record id) as well as enforcing capacity
// by insertion order. The collection is *not* thread safe.
type RecordCollection struct {
	records        map[string]recordCollectionNode
	insertionOrder *list.List
}

// NewRecordCollection creates a new RecordCollection.
func NewRecordCollection() *RecordCollection {
	return &RecordCollection{
		records:        map[string]recordCollectionNode{},
		insertionOrder: list.New(),
	}
}

// Delete deletes a record from the collection.
func (c *RecordCollection) Delete(recordID string) {
	node, ok := c.records[recordID]
	if !ok {
		return
	}
	delete(c.records, recordID)
	c.insertionOrder.Remove(node.insertionOrderPtr)
}

// Get gets a record from the collection.
func (c *RecordCollection) Get(recordID string) *databroker.Record {
	node, ok := c.records[recordID]
	if !ok {
		return nil
	}
	return node.Record
}

// Len returns the length of the collection.
func (c *RecordCollection) Len() int {
	return len(c.records)
}

// List lists all the records in the collection in insertion order.
func (c *RecordCollection) List() []*databroker.Record {
	var all []*databroker.Record
	for el := c.insertionOrder.Front(); el != nil; el = el.Next() {
		all = append(all, c.records[el.Value.(string)].Record)
	}
	return all
}

// Put puts a record in the collection.
func (c *RecordCollection) Put(record *databroker.Record) {
	c.Delete(record.GetId())

	el := c.insertionOrder.PushBack(record.GetId())
	c.records[record.GetId()] = recordCollectionNode{
		Record:            record,
		insertionOrderPtr: el,
	}
}
