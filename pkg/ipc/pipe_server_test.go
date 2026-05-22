package ipc

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pomerium/pomerium/pkg/grpc/testproto"
	"github.com/pomerium/pomerium/pkg/nullable"
)

func waitForErr(t *testing.T, ch <-chan error, timeout time.Duration, msg string) error {
	t.Helper()
	select {
	case err := <-ch:
		return err
	case <-time.After(timeout):
		t.Fatalf("timed out waiting for %s", msg)
		return nil
	}
}

func TestPipePair(t *testing.T) {
	t.Parallel()

	t.Run("close once", func(t *testing.T) {
		r, w, err := os.Pipe()
		require.NoError(t, err)
		pair := NewPipePair(r, w)

		first := pair.Close()
		second := pair.Close()
		assert.NoError(t, first)
		assert.Equal(t, first, second, "second close should be the same")
	})
}

func TestProtoPipeWorker(t *testing.T) {
	t.Parallel()

	t.Run("round-trip", func(t *testing.T) {
		client := newTestPipeClient[*testproto.Test, *testproto.Test](t)
		worker := client.worker()
		t.Cleanup(func() { _ = worker.Close() })

		echoHandler := &testServerHandler{
			handler: func(_ context.Context, msg *testproto.Test) (nullable.Value[*testproto.Test], error) {
				msg.StringField = msg.StringField + "!"
				return nullable.From(msg), nil
			},
		}

		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		errC := make(chan error, 1)
		go func() {
			errC <- worker.run(ctx, echoHandler)
		}()

		client.send(t, &testproto.Test{
			StringField: "hello",
		})
		assert.Equal(t, "hello!", client.recv(t).GetStringField())

		for i := range 8 {
			client.send(t, &testproto.Test{
				StringField: fmt.Sprintf("msg-%d", i),
			})
		}
		for i := range 8 {
			assert.Equal(t, fmt.Sprintf("msg-%d!", i), client.recv(t).GetStringField())
		}

		assert.NoError(t, worker.Close())
		assert.NoError(t, waitForErr(t, errC, 2*time.Second, "worker should exit"))
	})

	t.Run("handshake", func(t *testing.T) {
		client := newTestPipeClient[*testproto.Test, *testproto.Test](t)
		worker := client.worker()

		echoHandlerWithHandshake := &testServerHandler{
			handler: func(_ context.Context, msg *testproto.Test) (nullable.Value[*testproto.Test], error) {
				msg.StringField = msg.StringField + "!"
				return nullable.From(msg), nil
			},
			handshakeIn: func(_ context.Context, r io.Reader) error {
				buf := [4]byte{}
				n, err := r.Read(buf[:])
				if err != nil {
					return err
				}
				if n != len(buf) {
					return fmt.Errorf("failed to read required number of bytes")
				}
				if !bytes.Equal(buf[:], []byte("aaaa")) {
					return fmt.Errorf("invalid handshake data")
				}
				return nil
			},
			handshakeOut: func(_ context.Context, w io.Writer) error {
				_, err := w.Write([]byte("bbbb"))
				if err != nil {
					return err
				}
				return nil
			},
		}
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		errC := make(chan error, 1)
		go func() {
			errC <- worker.run(ctx, echoHandlerWithHandshake)
		}()

		client.sendRaw(t, []byte("aaaa"))
		readBuf := [4]byte{}
		client.recvRaw(t, readBuf[:])
		assert.Equal(t, []byte("bbbb"), readBuf[:])

		client.send(t, &testproto.Test{
			StringField: "hello",
		})
		assert.Equal(t, "hello!", client.recv(t).GetStringField())

		assert.NoError(t, worker.Close())
		assert.NoError(t, waitForErr(t, errC, 2*time.Second, "worker should exit"))
	})
}

func TestProtoPipeServer(t *testing.T) {
	t.Parallel()

	t.Run("round-trip", func(t *testing.T) {
		t.Parallel()
		echoHandler := &testServerHandler{
			handler: func(_ context.Context, msg *testproto.Test) (nullable.Value[*testproto.Test], error) {
				return nullable.From(msg), nil
			},
		}
		sc := newServersClient(t, 4,
			echoHandler,
		)

		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		sc.start(ctx)

		sc.runClients(func(i int, c *testPipeClient[*testproto.Test, *testproto.Test]) {
			for j := range 3 {
				val := int32(i*100 + j)
				c.send(t, &testproto.Test{StringField: fmt.Sprintf("msg-%d", val)})
				resp := c.recv(t)
				assert.Equal(t, fmt.Sprintf("msg-%d", val), resp.GetStringField(),
					"client %d round %d: response mismatch", i, j)
			}
		})
		assert.NoError(t, sc.server.Shutdown(t.Context()))
	})

	t.Run("handshake", func(t *testing.T) {
		t.Parallel()
		echoHandlerWithHandshake := &testServerHandler{
			handler: func(_ context.Context, msg *testproto.Test) (nullable.Value[*testproto.Test], error) {
				msg.StringField = msg.StringField + "!"
				return nullable.From(msg), nil
			},
			handshakeIn: func(_ context.Context, r io.Reader) error {
				buf := [4]byte{}
				n, err := r.Read(buf[:])
				if err != nil {
					return err
				}
				if n != len(buf) {
					return fmt.Errorf("failed to read required number of bytes")
				}
				if !bytes.Equal(buf[:], []byte("aaaa")) {
					return fmt.Errorf("invalid handshake data")
				}
				return nil
			},
			handshakeOut: func(_ context.Context, w io.Writer) error {
				_, err := w.Write([]byte("bbbb"))
				if err != nil {
					return err
				}
				return nil
			},
		}

		sc := newServersClient(t, 4,
			echoHandlerWithHandshake,
		)

		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		sc.start(ctx)

		sc.runClients(func(_ int, c *testPipeClient[*testproto.Test, *testproto.Test]) {
			c.sendRaw(t, []byte("aaaa"))
			readBuf := [4]byte{}
			c.recvRaw(t, readBuf[:])
			assert.Equal(t, []byte("bbbb"), readBuf[:])
		})

		sc.runClients(func(i int, c *testPipeClient[*testproto.Test, *testproto.Test]) {
			for j := range 3 {
				val := int32(i*100 + j)
				c.send(t, &testproto.Test{StringField: fmt.Sprintf("msg-%d", val)})
				resp := c.recv(t)
				assert.Equal(t, fmt.Sprintf("msg-%d!", val), resp.GetStringField(),
					"client %d round %d: response mismatch", i, j)
			}
		})

		assert.NoError(t, sc.server.Shutdown(t.Context()))
	})
}
