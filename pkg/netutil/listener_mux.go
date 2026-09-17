package netutil

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"
	"syscall"
	"time"

	"github.com/rs/zerolog"
	"golang.org/x/sys/unix"
)

type ListenerMux struct {
	listenersMu sync.RWMutex
	listeners   map[string]*proxyListenerChannels
	logger      zerolog.Logger
}

type proxyListenerChannels struct {
	accept chan<- acceptTuple
	closed <-chan struct{}
}

type acceptTuple struct {
	cc  net.Conn
	err error
}

// InitialRecvTimeout is the maximum time to wait between a connection being
// accepted and receiving either the first byte(s) that do not match a metadata
// header or the entire header. Can be modified for tests.
var InitialRecvTimeout = 1 * time.Second

const (
	magic0, magic1, magic2, magic3 = 0x37, 0x32, 0x36, 0x31
)

// NewListenerMux creates a new listener multiplexer that can distribute
// incoming connections to other listeners. Use with the initial_metadata
// extension to prepend the header to connections.
//
// The header format is the 4-byte identifier [0x37 0x32 0x36 0x31] followed by
// 1 byte containing the length of the payload, followed by the payload. The
// payload is a string corresponding to listener IDs passed to Listen(). The
// strings are not null-terminated.
//
// When a connection is accepted by any listener, if the first bytes written on
// the socket are a valid header and the payload string corresponds to a known
// listener ID, the header bytes will be drained from the socket and the
// connection will be handed off to the listener with that ID. If there is no
// header, the original listener receives the connection.
//
// Warning: this must only be used in situations where ALL listeners that will
// be attached to the ListenerMux have the same network reachability. Since a
// connection to any listener in the mux can be routed to any other listener
// in the mux, if e.g. one listener is public and one is internal, the public
// listener can be used to dial directly to the internal listener. The intended
// use for this is http/grpc multiplexing where both ports are publicly
// accessible and both servers have the same TLS configuration.
func NewListenerMux(logger zerolog.Logger) *ListenerMux {
	return &ListenerMux{
		listeners: make(map[string]*proxyListenerChannels),
		logger:    logger,
	}
}

// Listen is used in place of net.Listen. The third argument is an opaque ID
// that identifies this listener. It must be unique among listeners added to
// this ListenerMux. The ID can be re-used, but only after Close() is called on
// the returned listener, and it returns (with or without an error).
//
// The returned Listener can be used in the same way as any other net.Listener.
// There are no special requirements to use it. Closing the returned listener
// closes the real underlying listener.
func (lm *ListenerMux) Listen(network string, addr string, listenerID string) (net.Listener, error) {
	accept := make(chan acceptTuple)
	realListener, err := net.Listen(network, addr)
	if err != nil {
		return nil, err
	}

	ctx, ca := context.WithCancel(context.Background())

	lm.listenersMu.Lock()
	if _, ok := lm.listeners[listenerID]; ok {
		lm.listenersMu.Unlock()
		// Close() must return before Listen() can be called again with the same ID
		panic(fmt.Sprintf("listener with id '%s' already exists and is not yet closed", listenerID))
	}
	lm.listeners[listenerID] = &proxyListenerChannels{
		accept: accept,
		closed: ctx.Done(),
	}
	lm.listenersMu.Unlock()

	done := make(chan struct{})
	go func() {
		lm.acceptLoop(ctx, realListener, listenerID)
		lm.listenersMu.Lock()
		// close this under lock so that receivers unblocked on Close will need to
		// wait to acquire the writer lock if they decide to immediately call Listen
		// again, and at that time the listener with this ID will be removed from
		// lm.listeners
		close(done)
		delete(lm.listeners, listenerID)
		lm.listenersMu.Unlock()
	}()
	return &proxyListener{
		real:   realListener,
		accept: accept,
		close:  ca,
		closed: ctx.Done(),
		done:   done,
	}, nil
}

func (lm *ListenerMux) acceptLoop(listenerCtx context.Context, realListener net.Listener, listenerID string) {
	lm.logger.Debug().
		Str("source", listenerID).
		Msg("listener mux: start accept loop")
	defer lm.logger.Debug().
		Str("source", listenerID).
		Msg("listener mux: end accept loop")

	var wg sync.WaitGroup
	defer wg.Wait()
	for {
		sc, err := realListener.Accept()
		if err != nil {
			lm.logger.Debug().
				Err(err).
				Str("source", listenerID).
				Msg("listener mux: accept error")
			lm.listenersMu.RLock()
			self := lm.listeners[listenerID]
			lm.listenersMu.RUnlock()
			select {
			case self.accept <- acceptTuple{nil, err}:
			case <-self.closed:
				return
			}
		} else {
			ctxWithDeadline, ca := context.WithTimeout(listenerCtx, InitialRecvTimeout)
			wg.Go(func() {
				defer ca()
				lm.processAcceptedConn(ctxWithDeadline, sc, listenerID)
			})
		}
	}
}

func (lm *ListenerMux) processAcceptedConn(listenerCtx context.Context, sc net.Conn, listenerID string) {
	id, from, err := readListenerID(listenerCtx, sc, listenerID)
	if err != nil {
		lm.logger.Debug().
			Err(err).
			Str("source", listenerID).
			Msg("listener mux: error reading listener id from connection")
		sc.Close()
		return
	}
	peerAddr := sockaddrToString(from)
	lm.listenersMu.RLock()
	dest, ok := lm.listeners[id]
	lm.listenersMu.RUnlock()
	if !ok {
		// don't log arbitrary strings unless they are known listener ids,
		// they could contain garbage
		lm.logger.Warn().
			Str("peer", peerAddr).
			Str("source", listenerID).
			Msg("listener mux: read unknown listener id from connection")
		sc.Close()
		return
	}

	select {
	case dest.accept <- acceptTuple{sc, nil}:
		lm.logger.Debug().
			Err(err).
			Str("peer", peerAddr).
			Str("source", listenerID).
			Str("dest", id).
			Msg("listener mux: routing connection")
	case <-dest.closed:
		lm.logger.Error().
			Err(err).
			Str("peer", peerAddr).
			Str("source", listenerID).
			Str("dest", id).
			Msg("listener mux: failed to route connection, dest listener is closed")
		sc.Close()
		return
	}
}

type proxyListener struct {
	real interface {
		Close() error
		Addr() net.Addr
	}
	accept <-chan acceptTuple
	close  func()
	closed <-chan struct{}
	done   chan struct{}
}

// Accept implements [net.Listener].
func (p *proxyListener) Accept() (net.Conn, error) {
	select {
	case t := <-p.accept:
		return t.cc, t.err
	case <-p.closed:
		return nil, net.ErrClosed
	}
}

// Addr implements [net.Listener].
func (p *proxyListener) Addr() net.Addr {
	return p.real.Addr()
}

// Close implements [net.Listener].
func (p *proxyListener) Close() error {
	select {
	case <-p.closed:
		return net.ErrClosed
	default:
		p.close()
		err := p.real.Close()
		// This should never block for long. It's just to wait for acceptLoop to
		// return
		<-p.done
		return err
	}
}

func sockaddrToString(addr unix.Sockaddr) string {
	switch addr := addr.(type) {
	case nil:
		return "unavailable"
	case *unix.SockaddrInet4:
		return net.JoinHostPort(net.IP(addr.Addr[:]).String(), strconv.Itoa(addr.Port))
	case *unix.SockaddrInet6:
		return net.JoinHostPort(net.IP(addr.Addr[:]).String(), strconv.Itoa(addr.Port))
	case *unix.SockaddrUnix:
		return addr.Name
	default:
		return fmt.Sprintf("%#v", addr)
	}
}

func readListenerID(listenerCtx context.Context, sc net.Conn, defaultID string) (string, unix.Sockaddr, error) {
	listenerID := defaultID
	var rawConn syscall.RawConn
	if syscallConn, ok := sc.(syscall.Conn); ok {
		var err error
		rawConn, err = syscallConn.SyscallConn()
		if err != nil {
			return "", nil, err
		}
	}

	const magicLen int = 4
	const payloadLenLen int = 1
	const headerLen int = magicLen + payloadLenLen
	magic := [magicLen]byte{magic0, magic1, magic2, magic3}

	var ctrlErr error
	var foundHeader bool
	var payloadLen int
	var peerAddr unix.Sockaddr
	// If the listener we accepted a connection from is closed before that
	// connection can be routed to a destination listener, we must close the
	// connection to preserve the semantics of Accept().
	stop := context.AfterFunc(listenerCtx, func() {
		// unblocks rawConn.Read if necessary
		sc.Close()
	})
	err := rawConn.Read(func(fd uintptr) bool {
		var header [headerLen]byte
		n, _, err := unix.Recvfrom(int(fd), header[:], unix.MSG_PEEK)
		if err != nil {
			if errors.Is(err, unix.EAGAIN) || errors.Is(err, unix.EINTR) {
				return false
			}
			ctrlErr = err
			return true
		}
		if n < len(header) {
			lim := min(n, len(magic))
			//nolintnextline:staticcheck
			if bytes.Equal(header[:lim], magic[:lim]) {
				return false
			}
			return true
		}
		if bytes.Equal(header[:magicLen], magic[:]) {
			foundHeader = true
			payloadLenBytes := header[magicLen:]
			switch len(payloadLenBytes) {
			case payloadLenLen:
				payloadLen = int(payloadLenBytes[0])
			case 2, 4, 8:
				fallthrough
			default:
				panic("unreachable")
			}
		}
		peerAddr, _ = unix.Getpeername(int(fd))
		return true
	})
	stopped := stop()
	if err != nil {
		return "", nil, err
	}
	if ctrlErr != nil {
		return "", nil, ctrlErr
	}
	if !stopped {
		// the connection was already closed
		return "", nil, net.ErrClosed
	}

	if foundHeader {
		buf := make([]byte, int(headerLen)+int(payloadLen)) //nolint:unconvert
		dl, _ := listenerCtx.Deadline()
		_ = sc.SetReadDeadline(dl)
		_, err := io.ReadFull(sc, buf[:])
		_ = sc.SetReadDeadline(time.Time{})
		if err != nil {
			return "", nil, err
		}
		listenerID = string(buf[headerLen:])
	}

	return listenerID, peerAddr, nil
}
