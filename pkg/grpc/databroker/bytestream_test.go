package databroker_test

import (
	"net"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/pomerium/pomerium/pkg/grpc/databroker"
)

func TestByteStream(t *testing.T) {
	t.Parallel()

	t.Run("server-side cancellation", func(t *testing.T) {
		t.Parallel()

		li, conn := startByteStreamConnection(t)
		assert.NoError(t, li.Close())

		n, err := conn.Read([]byte{1})
		assert.Error(t, err)
		assert.Equal(t, 0, n)

		n, err = conn.Write([]byte{1})
		assert.Error(t, err)
		assert.Equal(t, 0, n)
	})

	t.Run("sends data", func(t *testing.T) {
		t.Parallel()

		li, conn := startByteStreamConnection(t)

		var wg sync.WaitGroup
		wg.Add(1)
		go func() {
			defer wg.Done()

			conn, err := li.Accept()
			require.NoError(t, err)
			t.Cleanup(func() { _ = conn.Close() })

			buf := make([]byte, 1024)
			n, err := conn.Read(buf)
			assert.NoError(t, err)
			assert.Equal(t, "FROM CLIENT", string(buf[:n]))

			_, err = conn.Write([]byte("FROM SERVER"))
			assert.NoError(t, err)
		}()

		wg.Add(1)
		go func() {
			defer wg.Done()

			_, err := conn.Write([]byte("FROM CLIENT"))
			assert.NoError(t, err)

			buf := make([]byte, 1024)
			n, err := conn.Read(buf)
			assert.NoError(t, err)
			assert.Equal(t, "FROM SERVER", string(buf[:n]))
		}()

		wg.Wait()
	})
}

func startByteStreamConnection(t testing.TB) (net.Listener, net.Conn) {
	li, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = li.Close() })

	srv := databroker.NewByteStreamListener()
	s := grpc.NewServer()
	t.Cleanup(s.Stop)
	databroker.RegisterByteStreamServer(s, srv)
	go s.Serve(li)

	cc, err := grpc.NewClient(li.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	require.NoError(t, err)
	t.Cleanup(func() { _ = cc.Close() })

	conn, err := databroker.NewByteStreamConn(t.Context(), databroker.NewByteStreamClient(cc))
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })

	return srv, conn
}
