package grpcutil

import (
	"context"
	"sync"
	"time"

	"google.golang.org/grpc"
)

// A ClientConnManager manages gRPC client connections.
// Connections will be created using the set dial options
// and re-used for the same target. After not being used
// for the idle cleanup timeout, they will be closed and
// removed from the collection of managed connections.
type ClientConnManager interface {
	// ActiveClientConnCount returns the number of active client connections.
	ActiveClientConnCount() int
	// IdleClientConnCount returns the numbero of idle client connections.
	IdleClientConnCount() int
	// GetClientConn returns a client connection for the given target.
	GetClientConn(target string) grpc.ClientConnInterface
	// SetDialOptions sets the dial options. It will also close any active
	// connections.
	SetDialOptions(dialOptions ...grpc.DialOption)
}

type clientConnManager struct {
	idleTimeout time.Duration

	mu          sync.Mutex
	active      map[string]*clientConnManagerActiveClientConn
	idle        map[string]*clientConnManagerIdleClientConn
	dialOptions []grpc.DialOption
}

// NewClientConnManager creates a new ClientConnManager.
func NewClientConnManager(idleTimeout time.Duration, dialOptions ...grpc.DialOption) ClientConnManager {
	mgr := &clientConnManager{
		idleTimeout: idleTimeout,
		active:      make(map[string]*clientConnManagerActiveClientConn),
		idle:        make(map[string]*clientConnManagerIdleClientConn),
	}
	mgr.SetDialOptions(dialOptions...)
	return mgr
}

func (mgr *clientConnManager) ActiveClientConnCount() int {
	mgr.mu.Lock()
	cnt := len(mgr.active)
	mgr.mu.Unlock()
	return cnt
}

func (mgr *clientConnManager) IdleClientConnCount() int {
	mgr.mu.Lock()
	cnt := len(mgr.idle)
	mgr.mu.Unlock()
	return cnt
}

func (mgr *clientConnManager) GetClientConn(target string) grpc.ClientConnInterface {
	return clientConnManagerLazyClientConn{mgr, target}
}

func (mgr *clientConnManager) SetDialOptions(dialOptions ...grpc.DialOption) {
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
	mgr.dialOptions = append(dialOptions,
		grpc.WithIdleTimeout(0), // disable the idle timeout since we will close idle connections with our own timer
	)
}

func (mgr *clientConnManager) acquire(target string) (*grpc.ClientConn, error) {
	mgr.mu.Lock()
	defer mgr.mu.Unlock()

	activeCC, ok := mgr.active[target]
	if !ok {
		idleCC, ok := mgr.idle[target]
		if ok {
			// move from idle to active
			delete(mgr.idle, target)
			idleCC.timer.Stop()
			activeCC = &clientConnManagerActiveClientConn{
				target: target,
				cc:     idleCC.cc,
			}
		} else {
			// create a new active connection
			cc, err := grpc.NewClient(target, mgr.dialOptions...)
			if err != nil {
				return nil, err
			}
			activeCC = &clientConnManagerActiveClientConn{
				target: target,
				cc:     cc,
			}
		}
		mgr.active[target] = activeCC
	}

	activeCC.count++
	return activeCC.cc, nil
}

func (mgr *clientConnManager) cleanupIdleClientConn(target string) {
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

func (mgr *clientConnManager) release(target string) {
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
		mgr.idle[target] = &clientConnManagerIdleClientConn{
			target: target,
			cc:     activeCC.cc,
			timer: time.AfterFunc(mgr.idleTimeout, func() {
				mgr.cleanupIdleClientConn(target)
			}),
		}
	}
}

// a clientConnManagerIdleClientConn represents an idle client connection.
type clientConnManagerIdleClientConn struct {
	target string
	cc     *grpc.ClientConn
	timer  *time.Timer
}

// a clientConnManagerActiveClientConn represents an active client connection.
type clientConnManagerActiveClientConn struct {
	target string
	cc     *grpc.ClientConn
	count  int
}

// a clientConnManagerLazyClientConn will create (or reuse) an active client
// connection whenever any method is invoked or stream is created
type clientConnManagerLazyClientConn struct {
	mgr    *clientConnManager
	target string
}

func (lazyCC clientConnManagerLazyClientConn) Invoke(
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

func (lazyCC clientConnManagerLazyClientConn) NewStream(
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
