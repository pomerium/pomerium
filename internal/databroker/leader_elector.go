package databroker

import (
	"context"
	"fmt"
	"sync"

	"github.com/hashicorp/raft"
	"github.com/volatiletech/null/v9"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/log"
	databrokerpb "github.com/pomerium/pomerium/pkg/grpc/databroker"
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

type raftLeaderElector struct {
	closeCtx context.Context
	close    context.CancelFunc

	mu              sync.RWMutex
	electedLeaderID null.String
}

// NewRaftLeaderElector creates a new raft leader elector. Leaders are elected
// using the raft protocol.
func NewRaftLeaderElector(
	options config.DataBrokerOptions,
	srv databrokerpb.RaftServer,
	clientManager *ClientManager,
	onChange func(),
) LeaderElector {
	e := &raftLeaderElector{}
	e.closeCtx, e.close = context.WithCancel(context.Background())
	go e.run(options, srv, clientManager, onChange)
	return e
}

func (e *raftLeaderElector) ElectedLeaderID() null.String {
	e.mu.RLock()
	electedLeaderID := e.electedLeaderID
	e.mu.RUnlock()
	return electedLeaderID
}

func (e *raftLeaderElector) Stop() {
	e.close()
}

func (e *raftLeaderElector) run(
	options config.DataBrokerOptions,
	srv databrokerpb.RaftServer,
	clientManager *ClientManager,
	onChange func(),
) {
	r, err := NewRaft(options, srv, clientManager)
	if err != nil {
		log.Error().Err(err).Msg("databroker-raft-leader-elector: error creating raft node")
		return
	}
	defer r.Shutdown()

	change := make(chan raft.Observation, 1)
	observer := raft.NewObserver(change, true, func(_ *raft.Observation) bool { return true })
	r.RegisterObserver(observer)
	defer r.DeregisterObserver(observer)

	for {
		_, serverID := r.LeaderWithID()
		next := null.String{
			String: string(serverID),
			Valid:  serverID != "",
			Set:    serverID != "",
		}

		e.mu.Lock()
		prev := e.electedLeaderID
		e.electedLeaderID = next
		e.mu.Unlock()

		if prev != next && onChange != nil {
			log.Info().Str("elected-leader-id", next.String).Msg("databroker-raft-leader-elector: leader change")
			onChange()
		}

		select {
		case <-e.closeCtx.Done():
			return
		case observation := <-change:
			log.Info().
				Str("observation-type", fmt.Sprintf("%T", observation.Data)).
				Any("observation", observation.Data).
				Send()
		}
	}
}
