package store

import (
	"sync"

	"github.com/kentik/patricia"
	"github.com/kentik/patricia/string_tree"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/structpb"
)

const (
	indexField = "$index"
	cidrField  = "cidr"
)

type index struct {
	mu     sync.RWMutex
	byType map[string]*recordIndex
}

func newIndex() *index {
	idx := new(index)
	idx.clear()
	return idx
}

func (idx *index) clear() {
	idx.mu.Lock()
	defer idx.mu.Unlock()
	idx.byType = map[string]*recordIndex{}
}

func (idx *index) delete(typeURL, id string) {
	idx.mu.Lock()
	defer idx.mu.Unlock()

	ridx, ok := idx.byType[typeURL]
	if !ok {
		return
	}
	ridx.delete(id)

	if len(ridx.byID) == 0 {
		delete(idx.byType, typeURL)
	}
}

func (idx *index) find(typeURL, id string) proto.Message {
	idx.mu.RLock()
	defer idx.mu.RUnlock()

	ridx, ok := idx.byType[typeURL]
	if !ok {
		return nil
	}
	return ridx.find(id)
}

func (idx *index) get(typeURL, id string) proto.Message {
	idx.mu.RLock()
	defer idx.mu.RUnlock()

	ridx, ok := idx.byType[typeURL]
	if !ok {
		return nil
	}
	return ridx.get(id)
}

func (idx *index) set(typeURL, id string, msg proto.Message) {
	idx.mu.Lock()
	defer idx.mu.Unlock()

	ridx, ok := idx.byType[typeURL]
	if !ok {
		ridx = newRecordIndex()
		idx.byType[typeURL] = ridx
	}
	ridx.set(id, msg)
}

// a recordIndex indexes records for of a specific type
type recordIndex struct {
	byID     map[string]proto.Message
	byCIDRV4 *string_tree.TreeV4
	byCIDRV6 *string_tree.TreeV6
}

// newRecordIndex creates a new record index.
func newRecordIndex() *recordIndex {
	return &recordIndex{
		byID:     map[string]proto.Message{},
		byCIDRV4: string_tree.NewTreeV4(),
		byCIDRV6: string_tree.NewTreeV6(),
	}
}

func (idx *recordIndex) delete(id string) {
	r, ok := idx.byID[id]
	if !ok {
		return
	}

	delete(idx.byID, id)

	addr4, addr6 := getIndexCIDR(r)
	if addr4 != nil {
		idx.byCIDRV4.Delete(*addr4, func(payload, val string) bool {
			return payload == val
		}, id)
	}
	if addr6 != nil {
		idx.byCIDRV6.Delete(*addr6, func(payload, val string) bool {
			return payload == val
		}, id)
	}
}

func (idx *recordIndex) find(idOrString string) proto.Message {
	r, ok := idx.byID[idOrString]
	if ok {
		return r
	}

	addrv4, addrv6, _ := patricia.ParseIPFromString(idOrString)
	if addrv4 != nil {
		found, id := idx.byCIDRV4.FindDeepestTag(*addrv4)
		if found {
			return idx.byID[id]
		}
	}
	if addrv6 != nil {
		found, id := idx.byCIDRV6.FindDeepestTag(*addrv6)
		if found {
			return idx.byID[id]
		}
	}

	return nil
}

func (idx *recordIndex) get(id string) proto.Message {
	return idx.byID[id]
}

func (idx *recordIndex) set(id string, msg proto.Message) {
	_, ok := idx.byID[id]
	if ok {
		idx.delete(id)
	}

	idx.byID[id] = msg
	addr4, addr6 := getIndexCIDR(msg)
	if addr4 != nil {
		idx.byCIDRV4.Set(*addr4, id)
	}
	if addr6 != nil {
		idx.byCIDRV6.Set(*addr6, id)
	}
}

func getIndexCIDR(msg proto.Message) (*patricia.IPv4Address, *patricia.IPv6Address) {
	var s *structpb.Struct
	if sv, ok := msg.(*structpb.Value); ok {
		s = sv.GetStructValue()
	} else {
		s, _ = msg.(*structpb.Struct)
	}
	if s == nil {
		return nil, nil
	}

	f, ok := s.Fields[indexField]
	if !ok {
		return nil, nil
	}

	obj := f.GetStructValue()
	if obj == nil {
		return nil, nil
	}

	cf, ok := obj.Fields[cidrField]
	if !ok {
		return nil, nil
	}

	c := cf.GetStringValue()
	if c == "" {
		return nil, nil
	}

	addr4, addr6, _ := patricia.ParseIPFromString(c)
	return addr4, addr6
}
