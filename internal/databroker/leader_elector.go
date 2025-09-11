package databroker

import (
	"context"
	"sync"

	"github.com/hashicorp/raft"
	"github.com/rs/zerolog"
	"github.com/volatiletech/null/v9"
	oteltrace "go.opentelemetry.io/otel/trace"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/internal/telemetry"
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
	telemetry telemetry.Component

	closeCtx context.Context
	close    context.CancelFunc

	mu              sync.RWMutex
	electedLeaderID null.String
}

// NewRaftLeaderElector creates a new raft leader elector. It uses raft to
// elect a leader.
func NewRaftLeaderElector(
	tracerProvider oteltrace.TracerProvider,
	options config.DataBrokerOptions,
	onChange func(),
) LeaderElector {
	e := &raftLeaderElector{
		telemetry: *telemetry.NewComponent(tracerProvider, zerolog.DebugLevel, "databroker-raft-leader-elector"),
	}
	e.closeCtx, e.close = context.WithCancel(context.Background())
	go e.run(options, onChange)
	return e
}

func (e *raftLeaderElector) ElectedLeaderID() null.String {
	e.mu.RLock()
	electedLeaderID := e.electedLeaderID
	e.mu.RUnlock()
	return electedLeaderID
}

func (e *raftLeaderElector) Stop() {}

func (e *raftLeaderElector) run(
	options config.DataBrokerOptions,
	onChange func(),
) {
	r, err := e.init(options)
	if err != nil {
		return
	}
	defer r.Shutdown()

	change := make(chan raft.Observation, 1)
	observer := raft.NewObserver(change, true, func(_ *raft.Observation) bool { return true })
	r.RegisterObserver(observer)
	defer r.DeregisterObserver(observer)

	for {
		e.update(r, onChange)

		select {
		case <-e.closeCtx.Done():
			return
		case <-change:
		}
	}
}

func (e *raftLeaderElector) init(options config.DataBrokerOptions) (*raft.Raft, error) {
	ctx, op := e.telemetry.Start(context.Background(), "Init")
	defer op.Complete()

	r, err := NewRaft(options)
	if err != nil {
		log.Ctx(ctx).Error().Err(err).Msg("failed to create raft node")
		return nil, op.Failure(err)
	}

	return r, nil
}

func (e *raftLeaderElector) update(r *raft.Raft, onChange func()) {
	ctx, op := e.telemetry.Start(context.Background(), "Update")
	defer op.Complete()

	serverAddress, serverID := r.LeaderWithID()
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
		log.Ctx(ctx).Info().
			Str("elected-leader-id", next.String).
			Str("elected-leader-address", string(serverAddress)).
			Msg("leader change")
		onChange()
	}
}
