package raft_test

import (
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/volatiletech/null/v9"
	"go.opentelemetry.io/otel/trace/noop"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/databroker/raft"
	"github.com/pomerium/pomerium/pkg/cryptutil"
)

func TestStreamLayer(t *testing.T) {
	t.Parallel()

	t.Run("uninitialized", func(t *testing.T) {
		l := raft.NewStreamLayer(noop.NewTracerProvider())
		_, err := l.Accept()
		assert.ErrorIs(t, err, raft.ErrListenerNotAvailable)
		_, err = l.Dial("127.0.0.100:9001", time.Second)
		assert.ErrorIs(t, err, raft.ErrDialerNotAvailable)
	})

	if runtime.GOOS == "darwin" {
		t.Skip("skipping because 127.0.0.100 is not routed by default on macOS")
	}

	cfg := &config.Config{
		Options: &config.Options{
			SharedKey: cryptutil.NewBase64Key(),
		},
	}

	cfg1 := cfg.Clone()
	cfg1.Options.DataBroker.RaftBindAddress = null.StringFrom("127.0.0.100:9001")
	l1 := raft.NewStreamLayer(noop.NewTracerProvider())
	l1.OnConfigChange(t.Context(), cfg1)

	cfg2 := cfg.Clone()
	cfg2.Options.DataBroker.RaftBindAddress = null.StringFrom("127.0.0.100:9002")
	l2 := raft.NewStreamLayer(noop.NewTracerProvider())
	l2.OnConfigChange(t.Context(), cfg2)

	var wg sync.WaitGroup

	wg.Add(1)
	go func() {
		defer wg.Done()

		conn, err := l2.Dial("127.0.0.100:9001", 10*time.Second)
		require.NoError(t, err)

		buf := make([]byte, 1)

		n, err := conn.Write(buf)
		assert.NoError(t, err)
		assert.Equal(t, 1, n)

		n, err = conn.Read(buf)
		assert.NoError(t, err)
		assert.Equal(t, 1, n)

		assert.NoError(t, conn.Close())
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()

		conn, err := l1.Accept()
		require.NoError(t, err)

		buf := make([]byte, 1)
		n, err := conn.Read(buf)
		assert.NoError(t, err)
		assert.Equal(t, 1, n)

		n, err = conn.Write(buf)
		assert.NoError(t, err)
		assert.Equal(t, 1, n)

		assert.NoError(t, conn.Close())
	}()

	wg.Wait()
}
