package databroker_test

import (
	"bytes"
	"fmt"
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

	t.Run("chunking", func(t *testing.T) {
		t.Parallel()

		var read [][]byte
		batchSize := 4096
		expectedChunkCount := 10
		expectedLength := expectedChunkCount * batchSize
		expectedPayload := bytes.Repeat([]byte{'x'}, expectedLength)

		li, cc := startByteStreamConnection(t)

		var wg sync.WaitGroup
		wg.Add(1)
		go func() {
			defer wg.Done()

			sc, err := li.Accept()
			require.NoError(t, err)
			t.Cleanup(func() { _ = sc.Close() })

			// read each chunk until we've seen all of them
			for len(read) < expectedChunkCount {
				buf := make([]byte, expectedLength)
				n, err := sc.Read(buf)
				assert.NoError(t, err)
				read = append(read, buf[:n])
			}

			// write a single byte to indicate to the client that we're done
			sc.Write([]byte{1})
		}()

		wg.Add(1)
		go func() {
			defer wg.Done()

			_, err := cc.Write(expectedPayload)
			assert.NoError(t, err)

			// read a single byte to ensure the listener receives all the data
			_, err = cc.Read([]byte{1})
			assert.NoError(t, err)

			_ = cc.Close()
		}()

		wg.Wait()

		assert.Equal(t, expectedChunkCount, len(read))
		assert.Equal(t, expectedPayload, bytes.Join(read, []byte{}))
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
	t.Run("multiple", func(t *testing.T) {
		t.Parallel()

		li, err := net.Listen("tcp", "127.0.0.1:0")
		require.NoError(t, err)
		t.Cleanup(func() { _ = li.Close() })

		srv := databroker.NewByteStreamListener()
		s := grpc.NewServer()
		t.Cleanup(s.Stop)
		databroker.RegisterByteStreamServer(s, srv)
		go s.Serve(li)

		var wg sync.WaitGroup
		wg.Add(1)
		go func() {
			defer wg.Done()

			for range 100 {
				conn, err := srv.Accept()
				require.NoError(t, err)

				buf := make([]byte, 128)
				n, err := conn.Read(buf[:])
				assert.NoError(t, err)

				_, err = conn.Write(buf[:n])
				assert.NoError(t, err)

				assert.NoError(t, conn.Close())
			}

			assert.NoError(t, li.Close())
		}()

		for i := range 100 {
			wg.Add(1)
			go func() {
				defer wg.Done()

				buf := fmt.Append(nil, i)

				cc, err := grpc.NewClient(li.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
				require.NoError(t, err)

				conn, err := databroker.NewByteStreamConn(t.Context(), databroker.NewByteStreamClient(cc))
				require.NoError(t, err)

				n, err := conn.Write(buf)
				assert.NoError(t, err)
				assert.Equal(t, len(buf), n)

				response := make([]byte, 128)
				n, err = conn.Read(response)
				assert.NoError(t, err)
				assert.Equal(t, len(buf), n)
				assert.Equal(t, buf, response[:n])

				assert.NoError(t, conn.Close())
				assert.NoError(t, cc.Close())
			}()
		}

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
