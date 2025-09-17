package raft

import (
	"time"

	"github.com/hashicorp/raft"
	hclogzerolog "github.com/weastur/hclog-zerolog"

	"github.com/pomerium/pomerium/internal/log"
)

// transport defaults, taken from https://github.com/hashicorp/vault/blob/cad4ab8a5c3534f05ad687dec55bd0521953c9ea/physical/raft/raft.go#L1252
const (
	defaultTransportMaxPool        = 3
	defaultTimeout                 = 10 * time.Second
	defaultMsgpackUseNewTimeFormat = true
)

// NewTransport creates a new raft transport.
func NewTransport(streamLayer raft.StreamLayer) raft.Transport {
	return raft.NewNetworkTransportWithConfig(&raft.NetworkTransportConfig{
		Stream:                  streamLayer,
		Logger:                  hclogzerolog.NewWithCustomNameField(log.Logger().With().Logger(), "component").Named("raft-transport"),
		MaxPool:                 defaultTransportMaxPool,
		Timeout:                 defaultTimeout,
		MsgpackUseNewTimeFormat: defaultMsgpackUseNewTimeFormat,
	})
}
