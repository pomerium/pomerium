// Package raft wraps hashicorp/raft for pomerium.
package raft

import "github.com/hashicorp/raft"

// aliasing raft types for easier importing

type (
	Observation       = raft.Observation
	LeaderObservation = raft.LeaderObservation
)

var NewObserver = raft.NewObserver
