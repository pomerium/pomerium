package raft

import (
	"errors"
	"fmt"

	"github.com/hashicorp/raft"
	hclogzerolog "github.com/weastur/hclog-zerolog"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/log"
)

var ErrNoClusterID = errors.New("no cluster id defined")

// A Node is a raft node.
type Node interface {
	DeregisterObserver(*raft.Observer)
	LeaderWithID() (raft.ServerAddress, raft.ServerID)
	RegisterObserver(*raft.Observer)
	Shutdown() raft.Future
}

// NewNode creates a new raft Node.
func NewNode(streamLayer StreamLayer, options config.DataBrokerOptions) (Node, error) {
	if !options.ClusterNodeID.IsValid() {
		return nil, ErrNoClusterID
	}
	nodeID := options.ClusterNodeID.String

	conf := raft.DefaultConfig()
	conf.LocalID = raft.ServerID(nodeID)
	conf.Logger = hclogzerolog.NewWithCustomNameField(log.Logger().With().Logger(), "component").Named("raft-node")

	fsm := NewFSM()
	logs := NewLogStore()
	stable := NewStableStore()
	snaps := NewSnapshotStore()
	trans := NewTransport(streamLayer)

	r, err := raft.NewRaft(conf, fsm, logs, stable, snaps, trans)
	if err != nil {
		return nil, fmt.Errorf("error creating raft node: %w", err)
	}

	var configuration raft.Configuration
	for _, n := range options.ClusterNodes {
		configuration.Servers = append(configuration.Servers, raft.Server{
			Suffrage: raft.Voter,
			ID:       raft.ServerID(n.ID),
			Address:  raft.ServerAddress(n.RaftAddress.String),
		})
	}
	err = r.BootstrapCluster(configuration).Error()
	if err != nil {
		_ = r.Shutdown().Error()
		return nil, fmt.Errorf("error bootstrapping cluster: %w", err)
	}

	return r, nil
}
