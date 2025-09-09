package databroker_test

import (
	"net"
	"sync"
	"testing"
	"time"

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

		li, cc := startByteStreamConnection(t)
		assert.NoError(t, li.Close())

		n, err := cc.Read([]byte{1})
		assert.Error(t, err)
		assert.Equal(t, 0, n)

		n, err = cc.Write([]byte{1})
		assert.Error(t, err)
		assert.Equal(t, 0, n)
	})

	t.Run("client-side cancellation", func(t *testing.T) {
		t.Parallel()

		li, cc := startByteStreamConnection(t)
		assert.NoError(t, cc.Close())

		// the connection should be accepted
		sc, err := li.Accept()
		assert.NoError(t, err)
		assert.NotNil(t, sc)

		// but the first attempt to read or write it should definitely fail
		n, err := sc.Read([]byte{1})
		assert.Error(t, err)
		assert.Equal(t, 0, n)
		n, err = sc.Write([]byte{1})
		assert.Error(t, err)
		assert.Equal(t, 0, n)
	})

	t.Run("read deadline", func(t *testing.T) {
		t.Parallel()

		li, cc := startByteStreamConnection(t)

		sc, err := li.Accept()
		assert.NoError(t, err)
		_ = sc

		assert.NoError(t, cc.SetReadDeadline(time.Now().Add(time.Millisecond)))
		n, err := cc.Read([]byte{1})
		assert.Error(t, err)
		assert.Equal(t, 0, n)
	})

	t.Run("sends data", func(t *testing.T) {
		t.Parallel()

		li, cc := startByteStreamConnection(t)

		var wg sync.WaitGroup
		wg.Add(1)
		go func() {
			defer wg.Done()

			sc, err := li.Accept()
			require.NoError(t, err)
			t.Cleanup(func() { _ = sc.Close() })

			buf := make([]byte, 1024)
			n, err := sc.Read(buf)
			assert.NoError(t, err)
			assert.Equal(t, "FROM CLIENT", string(buf[:n]))

			_, err = sc.Write([]byte("FROM SERVER"))
			assert.NoError(t, err)
		}()

		wg.Add(1)
		go func() {
			defer wg.Done()

			_, err := cc.Write([]byte("FROM CLIENT"))
			assert.NoError(t, err)

			buf := make([]byte, 1024)
			n, err := cc.Read(buf)
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
