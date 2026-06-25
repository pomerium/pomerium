package ipc

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"golang.org/x/sync/errgroup"
	"golang.org/x/sys/unix"
	"google.golang.org/protobuf/encoding/protodelim"
	"google.golang.org/protobuf/proto"

	"github.com/pomerium/pomerium/internal/log"
)

func NewPipeWorkers[Recv proto.Message, Send proto.Message](
	num int,
) ([]*ProtoPipeWorker[Recv, Send], error) {
	ret := []*ProtoPipeWorker[Recv, Send]{}
	var retErr error
	for range num {
		worker, err := createWorker[Recv, Send]()
		if err != nil {
			retErr = err
			break
		}
		ret = append(ret, worker)
	}
	if retErr != nil {
		for _, worker := range ret {
			_ = worker.Close()
		}
		return nil, retErr
	}

	return ret, nil
}

func PipeClients[Recv proto.Message, Send proto.Message](workers []*ProtoPipeWorker[Recv, Send]) []*os.File {
	files := []*os.File{}
	for _, worker := range workers {
		files = append(files, worker.Sender.Read, worker.Receiver.Write)
	}
	return files
}

func createWorker[Recv proto.Message, Send proto.Message]() (*ProtoPipeWorker[Recv, Send], error) {
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
	return NewProtoPipeWorker(
		receiver,
		sender,
	), nil
}

func (p *PipePair) Close() error {
	return p.closeF()
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

// recvMsg cannot handle corrupted data / invalid protobuf since protodelim expects
// a varint to delim the next message size. Since an invalid parse can get "confused" and tell the
// protodelim reader to read a set number of bytes which may never come, we have to treat
// any parse error as non-recoverable.
// The only way to prevent this is to add something like PING frames so that the reader,
// when combined with a generic ReadDeadline can seek ahead and discard bytes it cannot
// read before the occasional PING frames.
func (r *ProtoPipeReceiver[Recv]) recvMsg() (Recv, error) {
	for {
		msg := newProtoMessage[Recv]()
		err := protodelim.UnmarshalFrom(r.rd, msg)
		if err == nil {
			return msg, nil
		}
		if !r.shutdownRequested() || !errors.Is(err, os.ErrDeadlineExceeded) {
			return msg, err
		}
		n, ferr := unix.IoctlGetInt(int(r.Read.Fd()), FIONREAD)
		if ferr != nil {
			var zero Recv
			return zero, ferr
		}
		if n == 0 {
			if cerr := r.Close(); cerr != nil {
				var zero Recv
				return zero, cerr
			}
			var zero Recv
			return zero, io.EOF
		}
		// clear the deadline so the next read can drain them
		if derr := r.Read.SetReadDeadline(time.Time{}); derr != nil {
			var zero Recv
			return zero, derr
		}
	}
}

func (s *ProtoPipeSender[Send]) sendMsg(_ context.Context, msg Send) error {
	if s.shutdownRequested() {
		if err := s.Close(); err != nil {
			return err
		}
	}
	if _, err := protodelim.MarshalTo(s.Write, msg); err != nil {
		return err
	}
	return nil
}

func (s *ProtoPipeSender[Send]) shutdownRequested() bool {
	return s.shouldShutdown.Load()
}

func (s *ProtoPipeSender[Send]) Shutdown() error {
	s.shouldShutdown.Store(true)
	return s.Write.SetWriteDeadline(time.Unix(1, 0))
}

func (w *ProtoPipeWorker[Recv, Send]) doHandshake(ctx context.Context, handler ServerHandler[Recv, Send]) error {
	eg, eCtx := errgroup.WithContext(ctx)
	eg.Go(func() error {
		if err := handler.RecvHandshake(eCtx, w.Receiver.Read); err != nil {
			log.Ctx(ctx).Err(err).Msg("server handshake failed")
			return fmt.Errorf("receive handshake failed")
		}
		return nil
	})
	eg.Go(func() error {
		if err := handler.SendHandshake(eCtx, w.Sender.Write); err != nil {
			return fmt.Errorf("send handshake failed")
		}
		return nil
	})
	return eg.Wait()
}

func (w *ProtoPipeWorker[Recv, Send]) run(ctx context.Context, handler ServerHandler[Recv, Send]) error {
	if err := w.doHandshake(ctx, handler); err != nil {
		return err
	}
	for {
		log.Ctx(ctx).Trace().Msg("waiting for message")
		msg, err := w.Receiver.recvMsg()
		if err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, os.ErrClosed) {
				return nil
			}
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return err
		}
		log.Ctx(ctx).Trace().Msg("passing received message to handler")
		resp, err := handler.Handler(ctx, msg)
		if err != nil {
			return err
		}
		if resp.IsSet {
			log.Ctx(ctx).Trace().Msg("sending response message")
			if err := w.Sender.sendMsg(ctx, resp.Value); err != nil {
				return err
			}
		}

		log.Ctx(ctx).Trace().Msg("sent response message")
	}
}

func (w *ProtoPipeWorker[Recv, Send]) Close() error {
	receiverCloseErr := w.Receiver.Close()
	senderCloseErr := w.Sender.Close()
	return errors.Join(receiverCloseErr, senderCloseErr)
}
