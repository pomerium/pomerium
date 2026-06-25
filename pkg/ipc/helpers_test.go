package ipc

import (
	"bufio"
	"context"
	"io"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/encoding/protodelim"
	"google.golang.org/protobuf/proto"

	"github.com/pomerium/pomerium/pkg/grpc/testproto"
	"github.com/pomerium/pomerium/pkg/nullable"
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

func (c *testPipeClient[Req, Resp]) sendRaw(t *testing.T, data []byte) {
	t.Helper()
	_, err := c.write.Write(data)
	require.NoError(t, err)
}

func (c *testPipeClient[Req, Resp]) recvRaw(t *testing.T, buf []byte) {
	t.Helper()
	_, err := c.read.Read(buf)
	require.NoError(t, err)
}

func (c *testPipeClient[Req, Resp]) recv(t *testing.T) Resp {
	t.Helper()
	msg := newProtoMessage[Resp]()
	require.NoError(t, protodelim.UnmarshalFrom(c.read, msg))
	return msg
}

type serversClient[Req, Resp proto.Message] struct {
	t        *testing.T
	server   *ProtoPipeServer[Req, Resp]
	clients  []*testPipeClient[Req, Resp]
	serveErr chan error
}

func makeClients[Req, Resp proto.Message](
	t *testing.T, n int,
) ([]*testPipeClient[Req, Resp], []*ProtoPipeWorker[Req, Resp]) {
	t.Helper()
	clients := make([]*testPipeClient[Req, Resp], n)
	workers := make([]*ProtoPipeWorker[Req, Resp], n)
	for i := range clients {
		clients[i] = newTestPipeClient[Req, Resp](t)
		workers[i] = clients[i].worker()
	}
	return clients, workers
}

func newServersClient[Req, Resp proto.Message](
	t *testing.T,
	n int,
	handler ServerHandler[Req, Resp],
) *serversClient[Req, Resp] {
	t.Helper()
	clients, workers := makeClients[Req, Resp](t, n)
	return &serversClient[Req, Resp]{
		t: t,
		server: NewProtoPipeServer(workers, handler, ServerOptions{
			ShutdownTimeout: time.Second * 15,
			Name:            "test",
		}),
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

type testServerHandler struct {
	handler      func(ctx context.Context, msg *testproto.Test) (nullable.Value[*testproto.Test], error)
	handshakeIn  func(context.Context, io.Reader) error
	handshakeOut func(context.Context, io.Writer) error
}

func (t *testServerHandler) RecvHandshake(ctx context.Context, rd io.Reader) error {
	if t.handshakeIn != nil {
		return t.handshakeIn(ctx, rd)
	}
	return nil
}

func (t *testServerHandler) SendHandshake(ctx context.Context, wr io.Writer) error {
	if t.handshakeOut != nil {
		return t.handshakeOut(ctx, wr)
	}
	return nil
}

func (t *testServerHandler) Handler(ctx context.Context, msg *testproto.Test) (nullable.Value[*testproto.Test], error) {
	return t.handler(ctx, msg)
}

var _ ServerHandler[*testproto.Test, *testproto.Test] = (*testServerHandler)(nil)
