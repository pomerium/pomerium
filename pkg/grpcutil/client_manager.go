package grpcutil

import (
	"context"
	"sync"
	"time"

	"github.com/rs/zerolog"
	oteltrace "go.opentelemetry.io/otel/trace"
	"google.golang.org/grpc"

	"github.com/pomerium/pomerium/internal/telemetry"
)

var (
	defaultClientManagerIdleTimeout = 30 * time.Second
	defaultClientManagerNewClient   = grpc.NewClient
)

type clientManagerConfig struct {
	idleTimeout time.Duration
	newClient   func(target string, options ...grpc.DialOption) (*grpc.ClientConn, error)
}

// A ClientManagerOption customizes the client manager config.
type ClientManagerOption func(cfg *clientManagerConfig)

// WithClientManagerIdleTimeout sets the idle timeout in the client manager config.
func WithClientManagerIdleTimeout(idleTimeout time.Duration) ClientManagerOption {
	return func(cfg *clientManagerConfig) {
		cfg.idleTimeout = idleTimeout
	}
}

// WithClientManagerNewClient sets the new client function in the client manager config.
func WithClientManagerNewClient(newClient func(target string, options ...grpc.DialOption) (*grpc.ClientConn, error)) ClientManagerOption {
	return func(cfg *clientManagerConfig) {
		cfg.newClient = newClient
	}
}

func getClientManagerConfig(options ...ClientManagerOption) *clientManagerConfig {
	cfg := new(clientManagerConfig)
	WithClientManagerIdleTimeout(defaultClientManagerIdleTimeout)(cfg)
	WithClientManagerNewClient(defaultClientManagerNewClient)(cfg)
	for _, option := range options {
		option(cfg)
	}
	return cfg
}

// A ClientManager manages gRPC client connections. Connections will be created
// using the new client function and re-used for the same target. After not
// being used for the idle cleanup timeout, they will be closed and removed
// from the collection of managed connections.
type ClientManager interface {
	// ActiveCount returns the number of active client connections.
	ActiveCount() int
	// GetClient returns a client connection for the given target.
	GetClient(target string) grpc.ClientConnInterface
	// IdleCount returns the numbero of idle client connections.
	IdleCount() int
	// UpdateOptions updates the options for the client manager.
	UpdateOptions(options ...ClientManagerOption)
}

type clientManager struct {
	telemetry telemetry.Component

	mu     sync.Mutex
	cfg    *clientManagerConfig
	active map[string]*clientManagerActiveClient
	idle   map[string]*clientManagerIdleClient
}

// NewClientManager creates a new ClientManager.
func NewClientManager(tracerProvider oteltrace.TracerProvider, options ...ClientManagerOption) ClientManager {
	return &clientManager{
		telemetry: *telemetry.NewComponent(tracerProvider, zerolog.TraceLevel, "grpc-client-manager"),
		active:    make(map[string]*clientManagerActiveClient),
		idle:      make(map[string]*clientManagerIdleClient),
		cfg:       getClientManagerConfig(options...),
	}
}

func (mgr *clientManager) ActiveCount() int {
	mgr.mu.Lock()
	cnt := len(mgr.active)
	mgr.mu.Unlock()
	return cnt
}

func (mgr *clientManager) GetClient(target string) grpc.ClientConnInterface {
	return clientManagerLazyClient{mgr, target}
}

func (mgr *clientManager) IdleCount() int {
	mgr.mu.Lock()
	cnt := len(mgr.idle)
	mgr.mu.Unlock()
	return cnt
}

func (mgr *clientManager) UpdateOptions(options ...ClientManagerOption) {
	_, op := mgr.telemetry.Start(context.Background(), "UpdateOptions")
	defer op.Complete()

	mgr.mu.Lock()
	defer mgr.mu.Unlock()

	// close any active connections
	for _, activeCC := range mgr.active {
		_ = activeCC.cc.Close()
	}
	clear(mgr.active)

	// close any idle connections
	for _, idleCC := range mgr.idle {
		_ = idleCC.cc.Close()
		idleCC.timer.Stop()
	}
	clear(mgr.idle)

	// update the dial options
	mgr.cfg = getClientManagerConfig(options...)
}

func (mgr *clientManager) acquire(target string) (*grpc.ClientConn, error) {
	_, op := mgr.telemetry.Start(context.Background(), "acquire")
	defer op.Complete()

	mgr.mu.Lock()
	defer mgr.mu.Unlock()

	activeCC, ok := mgr.active[target]
	if !ok {
		idleCC, ok := mgr.idle[target]
		if ok {
			// move from idle to active
			delete(mgr.idle, target)
			idleCC.timer.Stop()
			activeCC = &clientManagerActiveClient{
				target: target,
				cc:     idleCC.cc,
			}
		} else {
			// create a new active connection
			cc, err := mgr.cfg.newClient(target,
				grpc.WithIdleTimeout(0), // disable the idle timeout since we're handling this ourselves
			)
			if err != nil {
				return nil, err
			}
			activeCC = &clientManagerActiveClient{
				target: target,
				cc:     cc,
			}
		}
		mgr.active[target] = activeCC
	}

	activeCC.count++
	return activeCC.cc, nil
}

func (mgr *clientManager) cleanupIdleClient(target string) {
	_, op := mgr.telemetry.Start(context.Background(), "cleanupIdleClient")
	defer op.Complete()

	mgr.mu.Lock()
	defer mgr.mu.Unlock()

	idleCC, ok := mgr.idle[target]
	if !ok {
		// this can happen if the timer fires after an idle connection was made active
		// or the dial options were updated
		return
	}

	_ = idleCC.cc.Close()
	idleCC.timer.Stop()
	delete(mgr.idle, target)
}

func (mgr *clientManager) release(target string) {
	_, op := mgr.telemetry.Start(context.Background(), "release")
	defer op.Complete()

	mgr.mu.Lock()
	defer mgr.mu.Unlock()

	activeCC, ok := mgr.active[target]
	if !ok {
		return
	}

	activeCC.count--

	// if there are no more consumers, move the connection to idle
	if activeCC.count <= 0 {
		delete(mgr.active, target)
		mgr.idle[target] = &clientManagerIdleClient{
			target: target,
			cc:     activeCC.cc,
			timer: time.AfterFunc(mgr.cfg.idleTimeout, func() {
				mgr.cleanupIdleClient(target)
			}),
		}
	}
}

// a clientManagerIdleClient represents an idle client connection.
type clientManagerIdleClient struct {
	target string
	cc     *grpc.ClientConn
	timer  *time.Timer
}

// a clientManagerActiveClient represents an active client connection.
type clientManagerActiveClient struct {
	target string
	cc     *grpc.ClientConn
	count  int
}

// a clientManagerLazyClient will create (or reuse) an active client
// connection whenever any method is invoked or stream is created
type clientManagerLazyClient struct {
	mgr    *clientManager
	target string
}

func (lazyCC clientManagerLazyClient) Invoke(
	ctx context.Context,
	method string,
	args any,
	reply any,
	opts ...grpc.CallOption,
) error {
	actualCC, err := lazyCC.mgr.acquire(lazyCC.target)
	if err != nil {
		return err
	}
	return actualCC.Invoke(ctx, method, args, reply, append(opts, grpc.OnFinish(func(_ error) {
		lazyCC.mgr.release(lazyCC.target)
	}))...)
}

func (lazyCC clientManagerLazyClient) NewStream(
	ctx context.Context,
	desc *grpc.StreamDesc,
	method string,
	opts ...grpc.CallOption,
) (grpc.ClientStream, error) {
	actualCC, err := lazyCC.mgr.acquire(lazyCC.target)
	if err != nil {
		return nil, err
	}
	return actualCC.NewStream(ctx, desc, method, append(opts, grpc.OnFinish(func(_ error) {
		lazyCC.mgr.release(lazyCC.target)
	}))...)
}
