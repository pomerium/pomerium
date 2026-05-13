package ipc

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"reflect"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/sync/errgroup"
	"golang.org/x/sys/unix"
	"google.golang.org/protobuf/encoding/protodelim"
	"google.golang.org/protobuf/proto"
)

func NewPipeWorkers[Recv proto.Message, Send proto.Message](
	num int,
) ([]*ProtoPipeWorker[Recv, Send], error) {
	ret := []*ProtoPipeWorker[Recv, Send]{}
	for range num {
		recvRead, recvWrite, err := os.Pipe()
		if err != nil {
			return nil, err
		}

		sendRead, sendWrite, err := os.Pipe()
		if err != nil {
			return nil, err
		}

		receiver := NewProtoPipeReceiver[Recv](
			NewPipePair(recvRead, recvWrite),
		)
		sender := NewProtoPipeSender[Send](
			NewPipePair(sendRead, sendWrite),
		)

		ret = append(ret, NewProtoPipeWorker(
			receiver,
			sender,
		))
	}
	return ret, nil
}

// PipePair encapsulates the read/write ends of a pipe.
type PipePair struct {
	Read  *os.File
	Write *os.File

	closeF func() error
}

func NewPipePair(readEnd *os.File, writeEnd *os.File) *PipePair {
	return &PipePair{
		Read:  readEnd,
		Write: writeEnd,
		closeF: sync.OnceValue(func() error {
			readCloseErr := readEnd.Close()
			writeCloseErr := writeEnd.Close()
			return errors.Join(readCloseErr, writeCloseErr)
		}),
	}
}

func (p *PipePair) Close() error {
	return p.closeF()
}

// ProtoPipeReceiver receives length-delimited protobuf messages from the read
// end of a PipePair.
type ProtoPipeReceiver[Recv proto.Message] struct {
	*PipePair
	rd             protodelim.Reader
	shouldShutdown atomic.Bool
}

func NewProtoPipeReceiver[Recv proto.Message](pair *PipePair) *ProtoPipeReceiver[Recv] {
	return &ProtoPipeReceiver[Recv]{
		PipePair: pair,
		rd:       bufio.NewReader(pair.Read),
	}
}

// Shutdown signals the receiver to stop after draining any data currently
// queued in the kernel pipe buffer. Setting a past read deadline unblocks
// pending reads immediately.
func (r *ProtoPipeReceiver[Recv]) Shutdown() error {
	r.shouldShutdown.Store(true)
	return r.Read.SetReadDeadline(time.Unix(1, 0))
}

func (r *ProtoPipeReceiver[Recv]) shutdownRequested() bool {
	return r.shouldShutdown.Load()
}

func (r *ProtoPipeReceiver[Recv]) recvMsg(_ context.Context) (Recv, error) {
	if r.shutdownRequested() {
		n, err := unix.IoctlGetInt(int(r.Read.Fd()), FIONREAD)
		if err != nil {
			var zero Recv
			return zero, err
		}
		if n == 0 {
			// nothing queued up, safe to signal close
			if err := r.Close(); err != nil {
				var zero Recv
				return zero, err
			}
			var zero Recv
			return zero, io.EOF
		}
		// otherwise, continues to drain
	}
	msg := newProtoMessage[Recv]()
	if err := protodelim.UnmarshalFrom(r.rd, msg); err != nil {
		return msg, err
	}
	return msg, nil
}

// ProtoPipeSender sends length-delimited protobuf messages to the write end of
// a PipePair.
type ProtoPipeSender[Send proto.Message] struct {
	*PipePair
}

func NewProtoPipeSender[Send proto.Message](pair *PipePair) *ProtoPipeSender[Send] {
	return &ProtoPipeSender[Send]{PipePair: pair}
}

func (s *ProtoPipeSender[Send]) sendMsg(_ context.Context, msg Send) error {
	if _, err := protodelim.MarshalTo(s.Write, msg); err != nil {
		return err
	}
	return nil
}

// ProtoPipeWorker handles bi-directional communication between receivers and senders.
type ProtoPipeWorker[Recv proto.Message, Send proto.Message] struct {
	receiver *ProtoPipeReceiver[Recv]
	sender   *ProtoPipeSender[Send]
}

func NewProtoPipeWorker[Recv proto.Message, Send proto.Message](
	receiver *ProtoPipeReceiver[Recv],
	sender *ProtoPipeSender[Send],
) *ProtoPipeWorker[Recv, Send] {
	return &ProtoPipeWorker[Recv, Send]{
		receiver: receiver,
		sender:   sender,
	}
}

func (w *ProtoPipeWorker[Recv, Send]) run(ctx context.Context, handler ServerHandler[Recv, Send]) error {
	for {
		msg, err := w.receiver.recvMsg(ctx)
		if err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, os.ErrClosed) {
				return nil
			}
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return err
		}
		resp, err := handler(msg)
		if err != nil {
			return err
		}
		if err := w.sender.sendMsg(ctx, resp); err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return err
		}
	}
}

func (w *ProtoPipeWorker[Recv, Send]) Close() error {
	receiverCloseErr := w.receiver.Close()
	senderCloseErr := w.sender.Close()
	return errors.Join(receiverCloseErr, senderCloseErr)
}

type ServerHandler[Recv proto.Message, Send proto.Message] = func(Recv) (Send, error)

// ProtoPipeServer handles a bidirectional streaming server implementation for [req,resp] proto pairs
// on top of unix pipe transports.
// It is meant to be long-lived and the underlying workers can be swapped out for
// new-ones on demand.
type ProtoPipeServer[Recv proto.Message, Send proto.Message] struct {
	workers []*ProtoPipeWorker[Recv, Send]

	updateC chan []*ProtoPipeWorker[Recv, Send]

	handler ServerHandler[Recv, Send]

	serveC          chan error
	shutdownTimeout time.Duration
}

func NewProtoPipeServer[Recv proto.Message, Send proto.Message](
	workers []*ProtoPipeWorker[Recv, Send],
	handler ServerHandler[Recv, Send],
) *ProtoPipeServer[Recv, Send] {
	return &ProtoPipeServer[Recv, Send]{
		workers:         workers,
		updateC:         make(chan []*ProtoPipeWorker[Recv, Send], 8),
		handler:         handler,
		serveC:          make(chan error, 1),
		shutdownTimeout: time.Minute,
	}
}

func (srv *ProtoPipeServer[Recv, Send]) serve(ctx context.Context) error {
	eg, eCtx := errgroup.WithContext(ctx)
	for _, worker := range srv.workers {
		eg.Go(func() error {
			return worker.run(eCtx, srv.handler)
		})
	}
	return eg.Wait()
}

func (srv *ProtoPipeServer[Recv, Send]) Serve(ctx context.Context) error {
	for {
		go func() {
			srv.serveC <- srv.serve(ctx)
		}()
		select {
		case <-ctx.Done():
			<-srv.serveC
			return fmt.Errorf("proto pipe server done : %w", ctx.Err())
		case newWorkers := <-srv.updateC:
			if err := srv.Shutdown(ctx); err != nil {
				return err
			}
			srv.workers = newWorkers
		case err := <-srv.serveC:
			if err != nil && !errors.Is(err, context.Canceled) {
				return fmt.Errorf("unexpected serve error : %w", err)
			}
			return nil
		}
	}
}

func (srv *ProtoPipeServer[Recv, Send]) OnChange(
	workers []*ProtoPipeWorker[Recv, Send],
) {
	srv.updateC <- workers
}

func (srv *ProtoPipeServer[Recv, Send]) Shutdown(_ context.Context) error {
	errs := []error{}
	for _, worker := range srv.workers {
		if err := worker.receiver.Shutdown(); err != nil {
			errs = append(errs, err)
		}
	}
	select {
	case <-time.After(srv.shutdownTimeout):
		return fmt.Errorf("proto pipe server shutdown timed out: %w", errors.Join(errs...))
	case err := <-srv.serveC:
		if err != nil && !errors.Is(err, context.Canceled) {
			return err
		}
		return nil
	}
}

func newProtoMessage[T proto.Message]() T {
	var zero T
	t := reflect.TypeOf(zero)
	if t.Kind() == reflect.Pointer {
		return reflect.New(t.Elem()).Interface().(T)
	}
	return zero
}
