package storage

import (
	"cmp"
	"container/list"
	"fmt"
	"maps"
	"net/netip"
	"slices"

	"github.com/gaissmai/bart"
	set "github.com/hashicorp/go-set/v3"
	"google.golang.org/protobuf/proto"

	"github.com/pomerium/pomerium/pkg/grpc/databroker"
)

// A RecordCollection stores records. It supports id and ip addr indexing and ordering of
// records in insertion order. It is not thread-safe.
type RecordCollection interface {
	// All returns all of the databroker records as a slice. The slice is in insertion order.
	All() []*databroker.Record
	// Clear removes all the records from the collection.
	Clear()
	// Get returns a record based on the record id.
	Get(recordID string) (*databroker.Record, bool)
	// Len returns the number of records stored in the collection.
	Len() int
	// List returns all of the databroker records that match the given expression.
	List(filter FilterExpression) ([]*databroker.Record, error)
	// Newest returns the newest databroker record in the collection.
	Newest() (*databroker.Record, bool)
	// Oldest returns the oldest databroker record in the collection.
	Oldest() (*databroker.Record, bool)
	// Put puts a record into the collection. If the record's deleted at field is not nil, the record will
	// be removed from the collection.
	Put(record *databroker.Record)
	// SetOptions sets databroker options that should be enforced by the collection
	SetOptions(*databroker.Options)
}

type recordCollectionNode struct {
	*databroker.Record
	insertionOrderPtr *list.Element
}

type recordCollection struct {
	cidrIndex      bart.Table[[]string]
	records        map[string]recordCollectionNode
	insertionOrder *list.List

	indexMgr *IndexManager
}

// NewRecordCollection creates a new RecordCollection.
func NewRecordCollection() RecordCollection {
	return &recordCollection{
		records:        make(map[string]recordCollectionNode),
		insertionOrder: list.New(),
		indexMgr: NewIndexManager(func() Indexer {
			return NewBTreeIndexer(2)
		}),
	}
}

func (c *recordCollection) All() []*databroker.Record {
	l := make([]*databroker.Record, 0, len(c.records))
	for e := c.insertionOrder.Front(); e != nil; e = e.Next() {
		r, ok := c.records[e.Value.(string)]
		if ok {
			l = append(l, proto.CloneOf(r.Record))
		}
	}
	return l
}

func (c *recordCollection) Clear() {
	c.cidrIndex = bart.Table[[]string]{}
	clear(c.records)
	c.insertionOrder = list.New()
	c.indexMgr.Clear()
}

func (c *recordCollection) Get(recordID string) (*databroker.Record, bool) {
	node, ok := c.records[recordID]
	if !ok {
		return nil, false
	}
	return proto.CloneOf(node.Record), true
}

func (c *recordCollection) has(recordID string) bool {
	_, ok := c.records[recordID]
	return ok
}

func (c *recordCollection) Len() int {
	return len(c.records)
}

func (c *recordCollection) List(filter FilterExpression) ([]*databroker.Record, error) {
	if filter == nil {
		return c.All(), nil
	}

	switch expr := filter.(type) {
	case AndFilterExpression:
		var rss [][]*databroker.Record
		for _, e := range expr {
			rs, err := c.List(e)
			if err != nil {
				return nil, err
			}
			rss = append(rss, rs)
		}
		return intersection(rss), nil
	case OrFilterExpression:
		var rss [][]*databroker.Record
		for _, e := range expr {
			rs, err := c.List(e)
			if err != nil {
				return nil, err
			}
			rss = append(rss, rs)
		}
		return union(rss), nil
	case SimpleFilterExpression:
		if expr.Operator != FilterExpressionOperatorEquals {
			return nil, fmt.Errorf("unsupported filter expression operator: %s", expr.Operator)
		}
		switch {
		case slices.Equal(expr.Fields, []string{"id"}):
			l := make([]*databroker.Record, 0, 1)
			if node, ok := c.records[expr.ValueAsString()]; ok {
				l = append(l, node.Record)
			}
			return l, nil
		case slices.Equal(expr.Fields, []string{"$index"}):
			l := []*databroker.Record{}
			if prefix, err := netip.ParsePrefix(expr.ValueAsString()); err == nil {
				l = c.lookupPrefix(prefix)
			} else if addr, err := netip.ParseAddr(expr.ValueAsString()); err == nil {
				l = c.lookupAddr(addr)
			}
			return l, nil
		default:
			recordIDs, err := c.indexMgr.GetRelatedIDs(expr)
			if err != nil {
				return nil, err
			}
			l := []*databroker.Record{}
			for _, recordID := range recordIDs {
				record, ok := c.Get(recordID)
				if ok {
					l = append(l, record)
				}
			}
			return l, nil
		}
	default:
		return nil, fmt.Errorf("unknown expression type: %T", expr)
	}
}

func (c *recordCollection) Put(record *databroker.Record) {
	record = proto.CloneOf(record)

	if c.has(record.GetId()) {
		c.indexMgr.Delete(record.GetId(), record.GetData())
	}

	// first delete the record
	c.delete(record.GetId())
	if record.DeletedAt != nil {
		c.indexMgr.Delete(record.GetId(), record.GetData())
		return
	}

	// add it
	el := c.insertionOrder.PushBack(record.GetId())
	c.records[record.GetId()] = recordCollectionNode{
		Record:            record,
		insertionOrderPtr: el,
	}
	if prefix := GetRecordIndexCIDR(record.GetData()); prefix != nil {
		c.addIndex(*prefix, record.GetId())
	}

	c.indexMgr.Update(record.GetId(), record.GetData())
}

func (c *recordCollection) SetOptions(opts *databroker.Options) {
	c.indexMgr.SetIndexableFields(opts.GetIndexableFields(), c.All)
}

func (c *recordCollection) Newest() (*databroker.Record, bool) {
	e := c.insertionOrder.Back()
	if e == nil {
		return nil, false
	}

	node, ok := c.records[e.Value.(string)]
	if !ok {
		return nil, false
	}

	return node.Record, true
}

func (c *recordCollection) Oldest() (*databroker.Record, bool) {
	e := c.insertionOrder.Front()
	if e == nil {
		return nil, false
	}

	node, ok := c.records[e.Value.(string)]
	if !ok {
		return nil, false
	}

	return node.Record, true
}

func (c *recordCollection) addIndex(prefix netip.Prefix, recordID string) {
	c.cidrIndex.Modify(prefix, func(ids []string, _ bool) (_ []string, del bool) {
		ids = slices.DeleteFunc(ids, func(id string) bool { return id == recordID })
		ids = append(ids, recordID)
		return ids, false
	})
}

func (c *recordCollection) delete(recordID string) {
	node, ok := c.records[recordID]
	if !ok {
		return
	}

	// delete the record from the index if it's the current value stored there
	if prefix := GetRecordIndexCIDR(node.GetData()); prefix != nil {
		c.deleteIndex(*prefix, recordID)
	}

	delete(c.records, recordID)
	c.insertionOrder.Remove(node.insertionOrderPtr)
	c.indexMgr.Delete(recordID, node.GetData())
}

func (c *recordCollection) deleteIndex(prefix netip.Prefix, recordID string) {
	c.cidrIndex.Modify(prefix, func(ids []string, _ bool) (_ []string, del bool) {
		ids = slices.DeleteFunc(ids, func(id string) bool { return id == recordID })
		return ids, len(ids) == 0
	})
}

func compareRecords(a, b *databroker.Record) int {
	return cmp.Or(
		cmp.Compare(a.GetType(), b.GetType()),
		cmp.Compare(a.GetId(), b.GetId()),
	)
}

func (c *recordCollection) lookupPrefix(prefix netip.Prefix) []*databroker.Record {
	recordIDs, ok := c.cidrIndex.LookupPrefix(prefix)
	if !ok {
		return nil
	}

	l := make([]*databroker.Record, 0, len(recordIDs))
	for _, recordID := range slices.Backward(recordIDs) {
		node, ok := c.records[recordID]
		if ok {
			l = append(l, proto.CloneOf(node.Record))
		}
	}

	slices.SortFunc(l, compareRecords)
	return l
}

func (c *recordCollection) lookupAddr(addr netip.Addr) []*databroker.Record {
	recordIDs, ok := c.cidrIndex.Lookup(addr)
	if !ok {
		return nil
	}

	l := make([]*databroker.Record, 0, len(recordIDs))
	for _, recordID := range slices.Backward(recordIDs) {
		node, ok := c.records[recordID]
		if ok {
			l = append(l, proto.CloneOf(node.Record))
		}
	}
	slices.SortFunc(l, compareRecords)
	return l
}

func intersection(xs [][]*databroker.Record) []*databroker.Record {
	var final []*databroker.Record

	lookup := map[[2]string]int{}
	for _, x := range xs {
		for _, e := range x {
			lookup[[2]string{e.GetType(), e.GetId()}]++
		}
	}
	seen := set.New[[2]string](0)
	for _, x := range xs {
		for _, e := range x {
			if lookup[[2]string{e.GetType(), e.GetId()}] == len(xs) {
				if !seen.Contains([2]string{e.GetType(), e.GetId()}) {
					final = append(final, e)
					seen.Insert([2]string{e.GetType(), e.GetId()})
				}
			}
		}
	}
	return final
}

func union(xs [][]*databroker.Record) []*databroker.Record {
	var final []*databroker.Record
	seen := set.New[[2]string](0)
	for _, x := range xs {
		for _, e := range x {
			if !seen.Contains([2]string{e.GetType(), e.GetId()}) {
				final = append(final, e)
				seen.Insert([2]string{e.GetType(), e.GetId()})
			}
		}
	}
	return final
}

// QueryRecordCollections queries a map of record collections.
func QueryRecordCollections(
	recordCollections map[string]RecordCollection,
	req *databroker.QueryRequest,
) (*databroker.QueryResponse, error) {
	filter, err := FilterExpressionFromStruct(req.GetFilter())
	if err != nil {
		return nil, err
	}

	var cs []RecordCollection
	if req.Type == "" {
		for _, recordType := range slices.Sorted(maps.Keys(recordCollections)) {
			cs = append(cs, recordCollections[recordType])
		}
	} else {
		c, ok := recordCollections[req.Type]
		if ok {
			cs = append(cs, c)
		}
	}

	res := new(databroker.QueryResponse)
	for _, c := range cs {
		if record, ok := c.Newest(); ok {
			res.RecordVersion = max(res.RecordVersion, record.Version)
		}

		records, err := c.List(filter)
		if err != nil {
			return nil, err
		}

		for _, record := range records {
			if req.GetQuery() != "" && !MatchAny(record.GetData(), req.GetQuery()) {
				continue
			}

			res.Records = append(res.Records, record)
		}
	}

	var total int
	res.Records, total = databroker.ApplyOffsetAndLimit(
		res.Records,
		int(req.GetOffset()),
		int(req.GetLimit()),
	)
	res.TotalCount = int64(total)
	return res, nil
}
