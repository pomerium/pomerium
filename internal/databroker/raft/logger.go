package raft

import (
	"github.com/hashicorp/go-hclog"
	hclogzerolog "github.com/weastur/hclog-zerolog"

	"github.com/pomerium/pomerium/internal/log"
)

// newLogger creates a new hclog.Logger for raft that writes to the global
// logger with the given name as its component.
func newLogger(name string) hclog.Logger {
	return hclogzerolog.NewWithCustomNameField(log.Logger().With().Logger(), "component").Named(name)
}
