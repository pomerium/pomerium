package raft

import (
	"io"

	"github.com/hashicorp/raft"
)

// NewFSM creates a new raft fsm.
//
// The fsm discards all commands.
func NewFSM() raft.FSM {
	m := &fsm{}
	return m
}

// NewFSMSnapshot creates a new raft fsm snapshot.
//
// The fsm snapshot is just discarded.
func NewFSMSnapshot() raft.FSMSnapshot {
	s := &fsmSnapshot{}
	return s
}

type fsm struct{}

func (*fsm) Apply(*raft.Log) any {
	return nil
}

func (*fsm) Snapshot() (raft.FSMSnapshot, error) {
	return NewFSMSnapshot(), nil
}

func (*fsm) Restore(snapshot io.ReadCloser) error {
	_, _ = io.Copy(io.Discard, snapshot)
	_ = snapshot.Close()
	return nil
}

type fsmSnapshot struct{}

func (*fsmSnapshot) Persist(sink raft.SnapshotSink) error {
	return sink.Close()
}

func (*fsmSnapshot) Release() {
	// do nothing
}
