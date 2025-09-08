package databroker

import (
	"context"
	"math/rand/v2"
	"sync"
	"time"

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

	closeCtx context.Context
	close    context.CancelFunc

	mu  sync.Mutex
	fns []func(leaderID null.String)
}

func NewRandomLeaderElector(nodeIDs []string) LeaderElector {
	e := &randomLeaderElector{
		nodeIDs: nodeIDs,
	}
	e.closeCtx, e.close = context.WithCancel(context.Background())
	e.pickRandomLeaderLocked()
	go e.run()
	return e
}

func (e *randomLeaderElector) OnLeaderChange(fn func(leaderID null.String)) {
	go fn(e.currentLeaderID)
}

func (e *randomLeaderElector) Stop() {
	e.close()
}

func (e *randomLeaderElector) run() {
	ticker := time.NewTicker(3 * time.Second)
	defer ticker.Stop()

	for {
		e.mu.Lock()
		e.pickRandomLeaderLocked()
		for _, fn := range e.fns {
			go fn(e.currentLeaderID)
		}
		e.mu.Unlock()

		select {
		case <-e.closeCtx.Done():
			return
		case <-ticker.C:
		}
	}
}

func (e *randomLeaderElector) pickRandomLeaderLocked() {
	if len(e.nodeIDs) == 0 {
		e.currentLeaderID = null.StringFromPtr(nil)
	} else {
		e.currentLeaderID = null.StringFrom(e.nodeIDs[rand.IntN(len(e.nodeIDs))]) //nolint:gosec
	}
}
