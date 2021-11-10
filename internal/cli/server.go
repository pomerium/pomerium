package cli

import (
	"context"
	"errors"
	"io"
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

// ListenerStatus marks individual records as locked
type ListenerStatus interface {
	// Lock marks a particular ID locked and provides a function to be called on unlock
	SetListening(id string, onUnlock context.CancelFunc, addr string) error
	// IsListening checks whether particular ID is currently locked
	IsListening(id string) (listenAddr string, listening bool)
	// Unlock unlocks the ID and calls onUnlock function
	SetNotListening(id string) error
}

// Tunnel is abstraction over tcptunnel.Tunnel to allow mocking
type Tunnel interface {
	Run(context.Context, io.ReadWriter, tcptunnel.TunnelEvents) error
}

// NewTunnel abstracts tunnel creation for easy mocking
type NewTunnel func(id string) (Tunnel, string, error)

// Server implements both config and listener interfaces
type Server interface {
	pb.ConfigServer
	pb.ListenerServer
}

type server struct {
	sync.RWMutex
	ConfigProvider
	EventBroadcaster
	ListenerStatus
	*config
}

var (
	errNotFound         = errors.New("not found")
	errAlreadyListening = errors.New("already listening")
	errNotListening     = errors.New("not listening")
)

// NewServer creates new configuration management server
func NewServer(ctx context.Context, opts ...ServerOption) (Server, error) {
	srv := &server{
		ListenerStatus:   newListenerStatus(),
		EventBroadcaster: NewEventsBroadcaster(ctx),
	}

	for _, opt := range append(opts,
		withDefaultConfigProvider(),
	) {
		if err := opt(srv); err != nil {
			return nil, err
		}
	}

	return srv, nil
}

// ServerOption allows to customize certain behavior
type ServerOption func(*server) error

// WithConfigProvider customizes configuration persistence
func WithConfigProvider(cp ConfigProvider) ServerOption {
	return func(s *server) error {
		cfg, err := loadConfig(cp)
		if err != nil {
			return err
		}
		s.config = cfg
		s.ConfigProvider = cp
		return nil
	}
}

func withDefaultConfigProvider() ServerOption {
	return func(s *server) error {
		if s.ConfigProvider == nil {
			return WithConfigProvider(new(MemCP))(s)
		}
		return nil
	}
}

// MemCP is in-memory config provider
type MemCP struct {
	data []byte
}

// Load loads the configuration data
func (s *MemCP) Load() ([]byte, error) {
	return s.data, nil
}

// Save saves configuration data
func (s *MemCP) Save(data []byte) error {
	s.data = data
	return nil
}
