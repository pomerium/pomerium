package raft

import (
	"github.com/hashicorp/raft"
)

// NewSnapshotStore creates a new raft snapshot store.
//
// Snapshots are just discarded.
func NewSnapshotStore() raft.SnapshotStore {
	return raft.NewDiscardSnapshotStore()
}
