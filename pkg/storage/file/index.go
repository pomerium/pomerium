package file

import (
	"cmp"
	"net/netip"
	"slices"
	"time"

	"github.com/gaissmai/bart"
	"github.com/google/btree"

	databrokerpb "github.com/pomerium/pomerium/pkg/grpc/databroker"
	registrypb "github.com/pomerium/pomerium/pkg/grpc/registry"
)

const btreeDegree int = 16

type optionsNode struct {
	recordType string
	options    *databrokerpb.Options
}

type recordCIDRNode struct {
	recordType string
	recordID   string
	prefix     netip.Prefix
}

type recordCIDRIndex struct {
	table bart.Table[[]recordCIDRNode]
}

func newRecordCIDRIndex() *recordCIDRIndex {
	return &recordCIDRIndex{}
}

func (idx *recordCIDRIndex) add(node recordCIDRNode) {
	idx.table.Modify(node.prefix, func(nodes []recordCIDRNode, _ bool) ([]recordCIDRNode, bool) {
		nodes = slices.DeleteFunc(nodes, func(n recordCIDRNode) bool {
			return n == node
		})
		return append(nodes, node), false
	})
}

func (idx *recordCIDRIndex) delete(node recordCIDRNode) {
	idx.table.Modify(node.prefix, func(nodes []recordCIDRNode, _ bool) (_ []recordCIDRNode, del bool) {
		nodes = slices.DeleteFunc(nodes, func(n recordCIDRNode) bool {
			return n == node
		})
		return nodes, len(nodes) == 0
	})
}

func (idx *recordCIDRIndex) lookupAddr(recordType string, addr netip.Addr) []recordCIDRNode {
	nodes, ok := idx.table.Lookup(addr)
	if !ok {
		return nil
	}
	nodes = slices.Clone(nodes)

	if recordType == "" {
		return nodes
	}

	return slices.DeleteFunc(nodes, func(node recordCIDRNode) bool {
		return node.recordType != recordType
	})
}

func (idx *recordCIDRIndex) lookupPrefix(recordType string, prefix netip.Prefix) []recordCIDRNode {
	nodes, ok := idx.table.LookupPrefix(prefix)
	if !ok {
		return nil
	}
	nodes = slices.Clone(nodes)

	if recordType == "" {
		return nodes
	}

	return slices.DeleteFunc(nodes, func(node recordCIDRNode) bool {
		return node.recordType != recordType
	})
}

type registryServiceNode struct {
	kind      registrypb.ServiceKind
	endpoint  string
	expiresAt time.Time
}

type registryServiceIndex struct {
	byExpiresAt    *btree.BTreeG[registryServiceNode]
	byKindEndpoint *btree.BTreeG[registryServiceNode]
}

func newRegistryServiceIndex() *registryServiceIndex {
	return &registryServiceIndex{
		byExpiresAt: btree.NewG(btreeDegree, func(a, b registryServiceNode) bool {
			return cmp.Or(
				a.expiresAt.Compare(b.expiresAt),
				cmp.Compare(a.kind, b.kind),
				cmp.Compare(a.endpoint, b.endpoint),
			) < 0
		}),
		byKindEndpoint: btree.NewG(btreeDegree, func(a, b registryServiceNode) bool {
			return cmp.Or(
				cmp.Compare(a.kind, b.kind),
				cmp.Compare(a.endpoint, b.endpoint),
			) < 0
		}),
	}
}

func (idx *registryServiceIndex) add(svc *registrypb.Service, now time.Time, ttl time.Duration) {
	node := registryServiceNode{
		kind:      svc.GetKind(),
		endpoint:  svc.GetEndpoint(),
		expiresAt: now.Add(ttl),
	}

	// insert the node into the (kind, endpoint) index
	previous, ok := idx.byKindEndpoint.ReplaceOrInsert(node)
	if ok {
		// if a previous node existed for the same (kind, endpoint)
		// we need to remove it from the (expiresAt) index
		idx.byExpiresAt.Delete(previous)
	}
	idx.byExpiresAt.ReplaceOrInsert(node)

	// remove any expired services
	idx.cleanup(now)
}

func (idx *registryServiceIndex) list(now time.Time) []*registrypb.Service {
	// remove any expired services
	idx.cleanup(now)

	var svcs []*registrypb.Service
	idx.byKindEndpoint.Ascend(func(item registryServiceNode) bool {
		svcs = append(svcs, &registrypb.Service{Kind: item.kind, Endpoint: item.endpoint})
		return true
	})
	return svcs
}

func (idx *registryServiceIndex) cleanup(now time.Time) {
	var remove []registryServiceNode
	idx.byExpiresAt.AscendLessThan(registryServiceNode{
		expiresAt: now.Add(time.Nanosecond),
	}, func(item registryServiceNode) bool {
		remove = append(remove, item)
		return true
	})
	for _, item := range remove {
		idx.byExpiresAt.Delete(item)
		idx.byKindEndpoint.Delete(item)
	}
}
