package ipc

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

// TODO : prefer not to do this. synctest?
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
		client := newTestPipeClient[*wrapperspb.StringValue, *wrapperspb.StringValue](t)
		worker := client.worker()
		t.Cleanup(func() { _ = worker.Close() })

		handler := func(msg *wrapperspb.StringValue) (*wrapperspb.StringValue, error) {
			return &wrapperspb.StringValue{Value: msg.GetValue() + "!"}, nil
		}

		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		errC := make(chan error, 1)
		go func() {
			errC <- worker.run(ctx, handler)
		}()

		client.send(t, &wrapperspb.StringValue{Value: "hello"})
		assert.Equal(t, "hello!", client.recv(t).GetValue())

		for i := range 8 {
			client.send(t, &wrapperspb.StringValue{
				Value: fmt.Sprintf("msg-%d", i),
			})
		}

		for i := range 8 {
			assert.Equal(t, fmt.Sprintf("msg-%d!", i), client.recv(t).GetValue())
		}

		assert.NoError(t, worker.Close())
		assert.NoError(t, waitForErr(t, errC, 2*time.Second, "worker should exit"))
	})

	// TODO : test more edge cases
	// - around invalid proto typed messages
	// - around corrupted messages / completely random messages
	// - context cancellation
	// - send failures
	// - handler errors
}

func TestProtoPipeServer(t *testing.T) {
	t.Parallel()

	t.Run("round-trip", func(t *testing.T) {
		t.Parallel()
		sc := newServersClient(t, 4,
			func(msg *wrapperspb.Int32Value) (*wrapperspb.Int32Value, error) {
				return &wrapperspb.Int32Value{Value: msg.GetValue() + 1000}, nil
			},
		)

		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		sc.start(ctx)

		sc.runClients(func(i int, c *testPipeClient[*wrapperspb.Int32Value, *wrapperspb.Int32Value]) {
			for j := range 3 {
				val := int32(i*100 + j)
				c.send(t, &wrapperspb.Int32Value{Value: val})
				resp := c.recv(t)
				assert.Equal(t, val+1000, resp.GetValue(),
					"client %d round %d: response mismatch", i, j)
			}
			require.NoError(t, c.closeWrite())
		})

		assert.NoError(t, sc.waitServer(2*time.Second))
	})

	t.Run("on transport change", func(_ *testing.T) {
		// TODO :
	})

	// TODO : edgecases around context cancellation, et al
}
