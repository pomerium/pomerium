package netutil

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"sync"

	envoy_config_core_v3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	"github.com/google/uuid"

	"github.com/pomerium/pomerium/internal/log"
)

// A LocalAddress is a network address that is only accessible locally.
type LocalAddress interface {
	EnvoyAddress() *envoy_config_core_v3.Address
	GRPCTarget() string
	HTTPTransport() http.RoundTripper
	Port() (uint32, error)
	String() string
}

// NewLocalAddress creates a new LocalAddress. On linux this will be a random
// abstract unix socket. On darwin it will be a random unix socket in the
// temporary directory. On any other operating system it will be a random,
// local TCP address.
func NewLocalAddress() (LocalAddress, error) {
	switch runtime.GOOS {
	case "darwin":
		return NewLocalUnixAddress(), nil
	case "linux":
		return NewLocalAbstractUnixAddress(), nil
	default:
		return NewLocalTCPAddress()
	}
}

// NewLocalAbstractUnixAddress creates a new local address using a random
// abstract unix socket. This only works in Linux.
func NewLocalAbstractUnixAddress() LocalAddress {
	return newLocalAbstractUnixAddress()
}

// NewLocalTCPAddress creates a new local address using a randomly assigned
// port by starting a tcp listener on 127.0.0.1:0.
func NewLocalTCPAddress() (LocalAddress, error) {
	li, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, fmt.Errorf("netutil: error listening on random local port")
	}
	addr := li.Addr().String()
	_ = li.Close()

	_, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, fmt.Errorf("netutil: invalid port in local address")
	}

	port, err := strconv.ParseUint(portStr, 10, 32)
	if err != nil {
		return nil, fmt.Errorf("netutil: invalid port in local address")
	}

	return localTCPAddress{port: uint32(port)}, nil
}

// NewLocalUnixAddress creates a new local address as a unix socket in the
// operating system temporary directory.
func NewLocalUnixAddress() LocalAddress {
	return newLocalUnixAddress()
}

type localAbstractUnixAddress struct {
	path string
}

func (addr localAbstractUnixAddress) EnvoyAddress() *envoy_config_core_v3.Address {
	return &envoy_config_core_v3.Address{
		Address: &envoy_config_core_v3.Address_Pipe{
			Pipe: &envoy_config_core_v3.Pipe{
				Path: "@" + addr.path,
			},
		},
	}
}

func (addr localAbstractUnixAddress) GRPCTarget() string {
	return fmt.Sprintf("unix-abstract:%s", addr.path)
}

func (addr localAbstractUnixAddress) HTTPTransport() http.RoundTripper {
	transport, ok := http.DefaultTransport.(*http.Transport)
	if !ok {
		transport = new(http.Transport)
	}
	transport.DialContext = func(ctx context.Context, _, _ string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "unix", "\000"+addr.path)
	}
	return transport
}

func (addr localAbstractUnixAddress) Port() (uint32, error) {
	return 0, fmt.Errorf("abstract unix addresses do not have a port")
}

func (addr localAbstractUnixAddress) String() string {
	return fmt.Sprintf("unix://@%s", addr.path)
}

func newLocalAbstractUnixAddress() localAbstractUnixAddress {
	return localAbstractUnixAddress{path: uuid.New().String()}
}

type localTCPAddress struct {
	port uint32
}

func (addr localTCPAddress) EnvoyAddress() *envoy_config_core_v3.Address {
	return &envoy_config_core_v3.Address{
		Address: &envoy_config_core_v3.Address_SocketAddress{
			SocketAddress: &envoy_config_core_v3.SocketAddress{
				Protocol: envoy_config_core_v3.SocketAddress_TCP,
				Address:  "127.0.0.1",
				PortSpecifier: &envoy_config_core_v3.SocketAddress_PortValue{
					PortValue: addr.port,
				},
			},
		},
	}
}

func (addr localTCPAddress) GRPCTarget() string {
	return fmt.Sprintf("ipv4:127.0.0.1:%d", addr.port)
}

func (addr localTCPAddress) HTTPTransport() http.RoundTripper {
	return http.DefaultTransport
}

func (addr localTCPAddress) Port() (uint32, error) {
	return addr.port, nil
}

func (addr localTCPAddress) String() string {
	return fmt.Sprintf("tcp://127.0.0.1:%d", addr.port)
}

type localUnixAddress struct {
	path string
}

func newLocalUnixAddress() localUnixAddress {
	return localUnixAddress{path: filepath.Join(os.TempDir(), uuid.New().String()+".sock")}
}

func (addr localUnixAddress) EnvoyAddress() *envoy_config_core_v3.Address {
	return &envoy_config_core_v3.Address{
		Address: &envoy_config_core_v3.Address_Pipe{
			Pipe: &envoy_config_core_v3.Pipe{
				Path: addr.path,
				Mode: 0o0600,
			},
		},
	}
}

func (addr localUnixAddress) GRPCTarget() string {
	return fmt.Sprintf("unix:%s", addr.path)
}

func (addr localUnixAddress) HTTPTransport() http.RoundTripper {
	transport, ok := http.DefaultTransport.(*http.Transport)
	if !ok {
		transport = new(http.Transport)
	}
	transport.DialContext = func(ctx context.Context, _, _ string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "unix", addr.path)
	}
	return transport
}

func (addr localUnixAddress) Port() (uint32, error) {
	return 0, fmt.Errorf("unix addresses do not have a port")
}

func (addr localUnixAddress) String() string {
	return fmt.Sprintf("unix://%s", addr.path)
}

// A LocalListener is a network listener only accessible locally. It binds a
// new local address immediately. Calls to Listen will return the already
// bound listener. Subsequent calls to Listen will terminate any previous
// listener connections allowing the new listener to take over.
type LocalListener interface {
	Address() LocalAddress
	Close() error
	Listen() net.Listener
}

// NewLocalListener creates a new local listener. On linux this will be a
// random abstract unix socket. On darwin it will be a random unix socket in
// the temporary directory. On any other operating system it will be a random,
// local TCP address.
func NewLocalListener() (LocalListener, error) {
	switch runtime.GOOS {
	case "darwin":
		return NewLocalUnixListener()
	case "linux":
		return NewLocalAbstractUnixListener()
	default:
		return NewLocalTCPListener()
	}
}

// NewLocalAbstractUnixListener creates a new local listener using a random
// abstract unix socket. This only works in Linux.
func NewLocalAbstractUnixListener() (LocalListener, error) {
	addr := newLocalAbstractUnixAddress()

	li, err := net.Listen("unix", "\000"+addr.path)
	if err != nil {
		return nil, fmt.Errorf("netutil: error starting abstract unix listener: %w", err)
	}

	return newLocalListener(addr, li), nil
}

// NewLocalTCPListener creates a new local listener using a randomly assigned
// port by starting a tcp listener on 127.0.0.1:0.
func NewLocalTCPListener() (LocalListener, error) {
	li, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return nil, fmt.Errorf("netutil: error starting tcp listener: %w", err)
	}
	addr := li.Addr().String()

	_, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		_ = li.Close()
		return nil, fmt.Errorf("netutil: invalid port in local address")
	}

	port, err := strconv.ParseUint(portStr, 10, 32)
	if err != nil {
		_ = li.Close()
		return nil, fmt.Errorf("netutil: invalid port in local address")
	}

	return newLocalListener(localTCPAddress{port: uint32(port)}, li), nil
}

// NewLocalUnixAddress creates a new local listener as a unix socket in the
// operating system temporary directory.
func NewLocalUnixListener() (LocalListener, error) {
	addr := newLocalUnixAddress()

	li, err := net.Listen("unix", addr.path)
	if err != nil {
		return nil, fmt.Errorf("netutil: error starting unix listener: %w", err)
	}

	return newLocalListener(addr, li), nil
}

type acceptPayload struct {
	conn net.Conn
	err  error
}

type localListener struct {
	addr LocalAddress
	li   net.Listener
	in   chan acceptPayload

	closeCtx context.Context
	close    context.CancelCauseFunc

	mu      sync.Mutex
	current *localListenerHandler
}

func newLocalListener(addr LocalAddress, li net.Listener) *localListener {
	ll := &localListener{addr: addr, li: li, in: make(chan acceptPayload)}
	ll.closeCtx, ll.close = context.WithCancelCause(context.Background())
	go ll.run()
	return ll
}

func (ll *localListener) Address() LocalAddress {
	return ll.addr
}

func (ll *localListener) Close() error {
	ll.close(nil)
	return ll.li.Close()
}

func (ll *localListener) Listen() net.Listener {
	ll.mu.Lock()
	defer ll.mu.Unlock()

	if ll.current != nil {
		log.Info().
			Str("address", ll.addr.String()).
			Msg("netutil: releasing previous local listener")
		_ = ll.current.Close()
	}
	ll.current = newLocalListenerHandler(ll.closeCtx, ll)
	return ll.current
}

func (ll *localListener) run() {
	for {
		conn, err := ll.li.Accept()
		select {
		case <-ll.closeCtx.Done():
			return
		case ll.in <- acceptPayload{conn: conn, err: err}:
		}
	}
}

type localListenerHandler struct {
	ll *localListener

	closeCtx context.Context
	close    context.CancelCauseFunc
}

func newLocalListenerHandler(ctx context.Context, local *localListener) *localListenerHandler {
	h := &localListenerHandler{ll: local}
	h.closeCtx, h.close = context.WithCancelCause(ctx)
	return h
}

func (h *localListenerHandler) Accept() (net.Conn, error) {
	// new connections/errors will be sent over the local listener in channel
	select {
	case <-h.closeCtx.Done():
		return nil, context.Cause(h.closeCtx)
	case payload := <-h.ll.in:
		if payload.err != nil {
			return nil, payload.err
		}
		// wrap the net.Conn so that on close we stop the context after func
		conn := afterConnClose{Conn: payload.conn}
		// if the context is closed, close the connection
		conn.stop = context.AfterFunc(h.closeCtx, func() {
			_ = conn.Conn.Close()
		})
		return conn, nil
	}
}

func (h *localListenerHandler) Close() error {
	h.close(nil)
	return nil
}

func (h *localListenerHandler) Addr() net.Addr {
	return h.ll.li.Addr()
}

type afterConnClose struct {
	net.Conn
	stop func() bool
}

func (a afterConnClose) Close() error {
	err := a.Conn.Close()
	if a.stop != nil {
		a.stop()
	}
	return err
}
