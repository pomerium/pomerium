package databroker

import (
	"context"
	"errors"
	"io"
	"net"
	"time"

	"google.golang.org/grpc"
)

// The defaultByteStreamBufferSize is used for buffering data to gRPC
// bytestream methods. It matches the default bufio buffer size.
const defaultByteStreamBufferSize = 4096

var errClosed = net.ErrClosed

type byteStreamAddr struct {
	target string
}

func (addr *byteStreamAddr) Network() string {
	return "grpc"
}

func (addr *byteStreamAddr) String() string {
	return "grpc://" + addr.target
}

// NewByteStreamConn creates a new net.Conn from a ByteStreamClient.
// If ctx is cancelled the net.Conn will be closed.
func NewByteStreamConn(ctx context.Context, client ByteStreamClient) (net.Conn, error) {
	conn := newByteStreamConn()

	ctx, cancel := context.WithCancelCause(ctx)
	stream, err := client.Connect(ctx)
	if err != nil {
		_ = conn.Close()
		cancel(errClosed)
		return nil, err
	}

	// receive data from the server
	go func() {
		for {
			chunk, err := stream.Recv()
			if errors.Is(err, io.EOF) {
				cancel(errClosed)
				return
			} else if err != nil {
				cancel(err)
				return
			}

			_, err = conn.recvWriter.Write(chunk.Data)
			if err != nil {
				cancel(err)
				return
			}
		}
	}()

	// send data to the server
	go func() {
		for {
			buf := make([]byte, defaultByteStreamBufferSize)
			n, err := conn.sendReader.Read(buf)
			if err != nil {
				cancel(err)
				return
			}

			chunk := &Chunk{Data: buf[:n]}
			err = stream.Send(chunk)
			if err != nil {
				cancel(err)
				return
			}
		}
	}()

	return conn, nil
}

// A ByteStreamListener is both a gRPC ByteStreamServer and a net.Listener.
type ByteStreamListener interface {
	ByteStreamServer
	net.Listener
}

type byteStreamListener struct {
	incoming chan net.Conn
	closeCtx context.Context
	close    context.CancelCauseFunc
}

// NewByteStreamListener creates a new ByteStreamListener.
func NewByteStreamListener() ByteStreamListener {
	li := &byteStreamListener{
		incoming: make(chan net.Conn),
	}
	li.closeCtx, li.close = context.WithCancelCause(context.Background())
	return li
}

func (li *byteStreamListener) Connect(stream grpc.BidiStreamingServer[Chunk, Chunk]) error {
	conn := newByteStreamConn()
	defer conn.Close()

	// start receiving/sending data in the background and use an error channel
	// to track any errors. On the first error, we return from the connection,
	// which will close the stream.
	errCh := make(chan error, 2)

	// receive data from the client
	go func() {
		for {
			chunk, err := stream.Recv()
			if errors.Is(err, io.EOF) {
				errCh <- errClosed
				return
			} else if err != nil {
				errCh <- err
				return
			}

			_, err = conn.recvWriter.Write(chunk.Data)
			if err != nil {
				errCh <- err
				return
			}
		}
	}()

	// send data to the client
	go func() {
		for {
			buf := make([]byte, defaultByteStreamBufferSize)
			n, err := conn.sendReader.Read(buf)
			if err != nil {
				errCh <- err
				return
			}

			chunk := &Chunk{Data: buf[:n]}
			err = stream.Send(chunk)
			if err != nil {
				errCh <- err
				return
			}
		}
	}()

	select {
	case li.incoming <- conn: // send the connection to the accept method
	case err := <-errCh: // the connection error'd out before we could accept it
		return err
	case <-li.closeCtx.Done(): // listener was closed
		return context.Cause(li.closeCtx)
	}

	// wait for an error or the listener to be closed
	select {
	case err := <-errCh:
		return err
	case <-li.closeCtx.Done():
		return context.Cause(li.closeCtx)
	}
}

func (li *byteStreamListener) Accept() (net.Conn, error) {
	select {
	case conn := <-li.incoming:
		return conn, nil
	case <-li.closeCtx.Done():
		return nil, context.Cause(li.closeCtx)
	}
}

func (li *byteStreamListener) Close() error {
	li.close(errClosed)
	return nil
}

func (li *byteStreamListener) Addr() net.Addr {
	return &byteStreamAddr{target: "server"}
}

type byteStreamConn struct {
	recvReader, recvWriter net.Conn
	sendReader, sendWriter net.Conn
}

func newByteStreamConn() *byteStreamConn {
	conn := &byteStreamConn{}
	conn.recvReader, conn.recvWriter = net.Pipe()
	conn.sendReader, conn.sendWriter = net.Pipe()
	return conn
}

func (conn *byteStreamConn) Read(b []byte) (int, error) {
	return conn.recvReader.Read(b)
}

func (conn *byteStreamConn) Write(b []byte) (int, error) {
	return conn.sendWriter.Write(b)
}

func (conn *byteStreamConn) Close() error {
	return errors.Join(
		conn.recvReader.Close(),
		conn.recvWriter.Close(),
		conn.sendReader.Close(),
		conn.sendWriter.Close(),
	)
}

func (conn *byteStreamConn) LocalAddr() net.Addr {
	return &byteStreamAddr{target: "client"}
}

func (conn *byteStreamConn) RemoteAddr() net.Addr {
	return &byteStreamAddr{target: "server"}
}

func (conn *byteStreamConn) SetDeadline(t time.Time) error {
	return errors.Join(conn.SetReadDeadline(t), conn.SetWriteDeadline(t))
}

func (conn *byteStreamConn) SetReadDeadline(t time.Time) error {
	return conn.recvReader.SetReadDeadline(t)
}

func (conn *byteStreamConn) SetWriteDeadline(t time.Time) error {
	return conn.sendWriter.SetWriteDeadline(t)
}
