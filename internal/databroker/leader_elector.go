package databroker

import (
	"math/rand/v2"

	"github.com/volatiletech/null/v9"
)

type LeaderElector interface {
	OnLeaderChange(func(leaderID null.String))
	Stop()
}

type staticLeaderElector struct {
	leaderID null.String
}

func NewStaticLeaderElector(leaderID null.String) LeaderElector {
	return &staticLeaderElector{
		leaderID: leaderID,
	}
}

func (e *staticLeaderElector) OnLeaderChange(fn func(leaderID null.String)) {
	go fn(e.leaderID)
}

func (e *staticLeaderElector) Stop() {}

type randomLeaderElector struct {
	nodeIDs         []string
	currentLeaderID null.String
}

func NewRandomLeaderElector(nodeIDs []string) LeaderElector {
	e := &randomLeaderElector{
		nodeIDs: nodeIDs,
	}
	if len(e.nodeIDs) > 0 {
		e.currentLeaderID = null.StringFrom(e.nodeIDs[rand.IntN(len(e.nodeIDs))]) //nolint:gosec
	}
	return e
}

func (e *randomLeaderElector) OnLeaderChange(fn func(leaderID null.String)) {
	go fn(e.currentLeaderID)
}

func (e *randomLeaderElector) Stop() {}
