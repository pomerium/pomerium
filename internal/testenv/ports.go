package testenv

import (
	"context"
	"fmt"
	"net"
	"sync"

	"github.com/pomerium/pomerium/pkg/netutil"
)

// reservedPorts holds every port AllocatePorts has handed out in this process.
//
// netutil.AllocatePorts works by binding ephemeral ports and immediately
// closing them, so the port numbers it returns are only reserved by convention:
// nothing stops the kernel from handing the same port to a later bind. Pomerium
// and envoy bind their share of those ports some time afterwards, so an
// in-process server binding to :0 in between can take one out from under them.
// When that happens envoy rejects the whole listener update ("failed to bind or
// apply socket options: cannot bind ...: Address already in use") and requests
// silently land on whichever server won the race.
//
// Holding the reservations open instead of tracking them is not an option:
// envoy only enables SO_REUSEPORT on linux (see config/envoyconfig.newListener),
// so elsewhere its bind would fail against a held-open socket, and on linux the
// kernel would load balance connections into the placeholder.
//
// Ports are never released, so that an environment shutting down cannot race an
// upstream starting up. The set stays small relative to the ephemeral port
// range: even a binary that builds dozens of environments reserves well under
// 1000 ports out of ~28000, so listenUnreserved rarely retries at all.
var reservedPorts sync.Map // string (port) -> struct{}

// listenMaxAttempts bounds the retry loop in listenUnreserved.
const listenMaxAttempts = 10

// AllocatePorts allocates ports for an environment's own listeners and reserves
// them, so Listen will not hand any of them to an in-process server.
func AllocatePorts(count int) ([]string, error) {
	ports, err := netutil.AllocatePorts(count)
	if err != nil {
		return nil, err
	}
	for _, port := range ports {
		reservedPorts.Store(port, struct{}{})
	}
	return ports, nil
}

// Listen starts a listener on an ephemeral port of host, skipping ports
// reserved by AllocatePorts. Servers running inside a test environment should
// use this instead of listening on :0 directly.
func Listen(ctx context.Context, host string) (net.Listener, error) {
	return listenUnreserved(ctx, host, func(port string) bool {
		_, reserved := reservedPorts.Load(port)
		return reserved
	})
}

func listenUnreserved(ctx context.Context, host string, isReserved func(port string) bool) (net.Listener, error) {
	var rejected []net.Listener
	defer func() {
		for _, li := range rejected {
			li.Close()
		}
	}()
	for range listenMaxAttempts {
		li, err := (&net.ListenConfig{}).Listen(ctx, "tcp", net.JoinHostPort(host, "0"))
		if err != nil {
			return nil, err
		}
		_, port, _ := net.SplitHostPort(li.Addr().String())
		if !isReserved(port) {
			return li, nil
		}
		// Hold the listener open so the next attempt gets a different port.
		rejected = append(rejected, li)
	}
	return nil, fmt.Errorf("no unreserved port available on %s after %d attempts", host, listenMaxAttempts)
}
