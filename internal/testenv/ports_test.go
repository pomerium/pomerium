package testenv

import (
	"context"
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// listenUnreserved must keep binding until it lands on a port the predicate
// accepts, rather than returning the first port it is given.
func TestListenUnreservedRetriesUntilAccepted(t *testing.T) {
	t.Parallel()

	const reject = 3
	var offered []string
	li, err := listenUnreserved(context.Background(), "127.0.0.1", func(port string) bool {
		if len(offered) < reject {
			offered = append(offered, port)
			return true
		}
		return false
	})
	require.NoError(t, err)
	t.Cleanup(func() { li.Close() })

	_, port, err := net.SplitHostPort(li.Addr().String())
	require.NoError(t, err)
	assert.Len(t, offered, reject, "should have kept retrying")
	assert.NotContains(t, offered, port, "returned a port the predicate rejected")
}

func TestListenUnreservedGivesUp(t *testing.T) {
	t.Parallel()

	attempts := 0
	li, err := listenUnreserved(context.Background(), "127.0.0.1", func(string) bool {
		attempts++
		return true
	})
	if li != nil {
		li.Close()
	}
	require.Error(t, err)
	assert.Equal(t, listenMaxAttempts, attempts)
}

// Ports handed out for an environment's own listeners must be off limits to
// Listen, otherwise an upstream can bind one before envoy does.
func TestAllocatePortsAreReserved(t *testing.T) {
	t.Parallel()

	ports, err := AllocatePorts(4)
	require.NoError(t, err)
	require.Len(t, ports, 4)

	for _, port := range ports {
		_, reserved := reservedPorts.Load(port)
		assert.Truef(t, reserved, "port %s was not reserved", port)
	}
}
