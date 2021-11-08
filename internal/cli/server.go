package cli

import (
	"context"

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

// ListenerStatus marks individual records as locked
type ListenerStatus interface {
	// Lock marks a particular ID locked and provides a function to be called on unlock
	SetListening(id string, onUnlock context.CancelFunc, addr string) error
	// IsListening checks whether particular ID is currently locked
	IsListening(id string) (listenAddr string, listening bool)
	// Unlock unlocks the ID and calls onUnlock function
	SetNotListening(id string) error
}

// Server implements both config and listener interfaces
type Server interface {
	pb.ConfigServer
	pb.ListenerServer
}

// NewServer creates new configuration management server
func NewServer(ctx context.Context, cp ConfigProvider) (Server, error) {
	cfg, err := loadConfig(cp)
	if err != nil {
		return nil, err
	}

	return &server{
		ConfigProvider:   cp,
		config:           cfg,
		ListenerStatus:   newListenerStatus(),
		EventBroadcaster: NewEventsBroadcaster(ctx),
	}, nil
}
