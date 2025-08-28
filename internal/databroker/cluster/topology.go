package cluster

import (
	"cmp"
	"slices"
)

// A Node is a databroker cluster node.
type Node struct {
	IsLeader      bool
	IsLocal       bool
	URL           string
	NodeID        uint64
	ServerVersion uint64
}

// Merge merges a node with another node.
func (node Node) Merge(other Node) Node {
	return Node{
		IsLeader:      cmp.Or(node.IsLeader, other.IsLeader),
		IsLocal:       cmp.Or(node.IsLocal, other.IsLocal),
		URL:           cmp.Or(node.URL, other.URL),
		NodeID:        cmp.Or(node.NodeID, other.NodeID),
		ServerVersion: cmp.Or(node.ServerVersion, other.ServerVersion),
	}
}

// A Topology describes all of a cluster's nodes and their status.
type Topology struct {
	Nodes []Node
}

func (topology Topology) Equals(other Topology) bool {
	return slices.Equal(topology.Nodes, other.Nodes)
}

// A TopologySource describes a cluster's topology and sends it to
// a listener.
type TopologySource interface {
	// Bind listens for changes to the cluster topology.
	// If available, it will send the current topology immediately.
	Bind() chan Topology
	// Unbind stops listening for changes to the cluster topology.
	Unbind(ch chan Topology)
	// Stop stops the topology source.
	Stop()
}
