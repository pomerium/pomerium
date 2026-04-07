package raft

import (
	"maps"
	"slices"
	"sync"

	"github.com/hashicorp/raft"
)

var globalRaftState = struct {
	mu        sync.RWMutex
	nodes     map[int]globalRaftNode
	nextIndex int
}{
	nodes: make(map[int]globalRaftNode),
}

type globalRaftNode struct {
	*raft.Raft
	index int
}

func addGlobalRaftNode(r *raft.Raft) Node {
	globalRaftState.mu.Lock()
	defer globalRaftState.mu.Unlock()

	n := globalRaftNode{
		Raft:  r,
		index: globalRaftState.nextIndex,
	}
	globalRaftState.nextIndex++
	globalRaftState.nodes[n.index] = n
	return n
}

func (n globalRaftNode) Shutdown() raft.Future {
	globalRaftState.mu.Lock()
	delete(globalRaftState.nodes, n.index)
	globalRaftState.mu.Unlock()

	return n.Raft.Shutdown()
}

// Stats returns raft debugging stats.
func Stats() []map[string]string {
	globalRaftState.mu.RLock()
	defer globalRaftState.mu.RUnlock()

	var ms []map[string]string
	idxs := slices.Sorted(maps.Keys(globalRaftState.nodes))
	for _, idx := range idxs {
		n := globalRaftState.nodes[idx]
		m := maps.Clone(n.Stats())
		_, leaderID := n.LeaderWithID()
		m["leader"] = string(leaderID)
		ms = append(ms, m)
	}
	return ms
}
