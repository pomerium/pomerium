package cli

import (
	"context"
	"sync"

	"github.com/pomerium/pomerium/internal/tcptunnel"
	pb "github.com/pomerium/pomerium/pkg/grpc/cli"
)

// ConfigProvider provides interface to the configuration persistence
type ConfigProvider interface {
	// Load returns configuration data,
	// should not throw an error if underlying storage does not exist
	Load() ([]byte, error)
	// Save stores data into storage
	Save([]byte) error
}

// RecordLocker marks individual records as locked
type RecordLocker interface {
	// Lock marks a particular ID locked and provides a function to be called on unlock
	LockRecord(id string, onUnlock context.CancelFunc) error
	// IsLocked checks whether particular ID is currently locked
	IsLocked(id string) bool
	// Unlock unlocks the ID and calls onUnlock function
	UnlockRecord(id string) error
}

// TunnelProvider is abstraction over tunnel creation by ID
type TunnelProvider interface {
	NewTunnel(id string) (*tcptunnel.Tunnel, string, error)
}

// Server implements both config and listener interfaces
type Server interface {
	pb.ConfigServer
	pb.ListenerServer
}

type tunnelProvider struct{ *config }

func (tp *tunnelProvider) NewTunnel(id string) (*tcptunnel.Tunnel, string, error) {
	rec, there := tp.byID[id]
	if !there {
		return nil, "", errNotFound
	}
	return newTunnel(rec.GetConn())
}

// NewServer creates new configuration management server
func NewServer(ctx context.Context, cp ConfigProvider) (Server, error) {
	locker := new(sync.Mutex)
	cfg, err := loadConfig(cp)
	if err != nil {
		return nil, err
	}

	cs := &configServer{
		ConfigProvider: cp,
		Locker:         locker,
		config:         cfg,
	}

	ls := &listenerServer{
		Locker:           locker,
		RecordLocker:     newRecordLocker(),
		TunnelProvider:   &tunnelProvider{cfg},
		EventBroadcaster: NewEventsBroadcaster(ctx),
	}

	return struct {
		*configServer
		*listenerServer
	}{cs, ls}, nil
}
