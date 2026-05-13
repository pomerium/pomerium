package ipc

import (
	"bufio"
	"context"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/encoding/protodelim"
	"google.golang.org/protobuf/proto"
)

type testPipeClient[Req, Resp proto.Message] struct {
	receiver *ProtoPipeReceiver[Req]
	sender   *ProtoPipeSender[Resp]
	write    *os.File
	read     protodelim.Reader
}

func newTestPipeClient[Req, Resp proto.Message](t *testing.T) *testPipeClient[Req, Resp] {
	t.Helper()
	serverRead, testWrite, err := os.Pipe()
	require.NoError(t, err)
	testRead, serverWrite, err := os.Pipe()
	require.NoError(t, err)
	return &testPipeClient[Req, Resp]{
		receiver: NewProtoPipeReceiver[Req](NewPipePair(serverRead, testWrite)),
		sender:   NewProtoPipeSender[Resp](NewPipePair(testRead, serverWrite)),
		write:    testWrite,
		read:     bufio.NewReader(testRead),
	}
}

func (c *testPipeClient[Req, Resp]) worker() *ProtoPipeWorker[Req, Resp] {
	return NewProtoPipeWorker(c.receiver, c.sender)
}

func (c *testPipeClient[Req, Resp]) send(t *testing.T, msg Req) {
	t.Helper()
	_, err := protodelim.MarshalTo(c.write, msg)
	require.NoError(t, err)
}

func (c *testPipeClient[Req, Resp]) recv(t *testing.T) Resp {
	t.Helper()
	msg := newProtoMessage[Resp]()
	require.NoError(t, protodelim.UnmarshalFrom(c.read, msg))
	return msg
}

func (c *testPipeClient[Req, Resp]) closeWrite() error {
	return c.write.Close()
}

type serversClient[Req, Resp proto.Message] struct {
	t        *testing.T
	server   *ProtoPipeServer[Req, Resp]
	clients  []*testPipeClient[Req, Resp]
	serveErr chan error
}

func newServersClient[Req, Resp proto.Message](
	t *testing.T,
	n int,
	handler ServerHandler[Req, Resp],
) *serversClient[Req, Resp] {
	t.Helper()
	clients := make([]*testPipeClient[Req, Resp], n)
	workers := make([]*ProtoPipeWorker[Req, Resp], n)
	for i := range clients {
		clients[i] = newTestPipeClient[Req, Resp](t)
		workers[i] = clients[i].worker()
	}
	return &serversClient[Req, Resp]{
		t:        t,
		server:   NewProtoPipeServer(workers, handler),
		clients:  clients,
		serveErr: make(chan error, 1),
	}
}

func (sc *serversClient[Req, Resp]) start(ctx context.Context) {
	go func() {
		sc.serveErr <- sc.server.Serve(ctx)
	}()
}

func (sc *serversClient[Req, Resp]) runClients(fn func(i int, c *testPipeClient[Req, Resp])) {
	var wg sync.WaitGroup
	for i, c := range sc.clients {
		wg.Go(func() {
			fn(i, c)
		})
	}
	wg.Wait()
}

func (sc *serversClient[Req, Resp]) waitServer(timeout time.Duration) error {
	sc.t.Helper()
	return waitForErr(sc.t, sc.serveErr, timeout, "ListenAndServe to return")
}
