package databroker

import (
	"github.com/volatiletech/null/v9"
)

// A LeaderElector elects a leader from a cluster of nodes.
type LeaderElector interface {
	// ElectedLeaderID returns the current elected leader id.
	// A null string indicates that there is no leader.
	ElectedLeaderID() null.String
	// Stop stops the leader elector.
	Stop()
}

type staticLeaderElector struct {
	electedLeaderID null.String
}

// NewStaticLeaderElector creates a new static leader elector. It always
// returns the passed in leader id.
func NewStaticLeaderElector(electedLeaderID null.String) LeaderElector {
	return &staticLeaderElector{electedLeaderID: electedLeaderID}
}

func (e *staticLeaderElector) ElectedLeaderID() null.String {
	return e.electedLeaderID
}

func (e *staticLeaderElector) Stop() {}
