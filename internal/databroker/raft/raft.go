// Package raft wraps hashicorp/raft for pomerium.
package raft

import "github.com/hashicorp/raft"

// aliasing raft types for easier importing

type (
	Observation       = raft.Observation
	LeaderObservation = raft.LeaderObservation
)

var NewObserver = raft.NewObserver

func nilToZero[T any](ptr *T) T {
	var def T
	if ptr == nil {
		return def
	}
	return *ptr
}
