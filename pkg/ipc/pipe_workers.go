package ipc

import (
	"context"
	"errors"
	"io"
	"os"
	"time"

	"github.com/pomerium/pomerium/internal/log"
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

func (s *ProtoPipeSender[Send]) sendMsg(_ context.Context, msg Send) error {
	if _, err := protodelim.MarshalTo(s.Write, msg); err != nil {
		return err
	}
	return nil
}

func (w *ProtoPipeWorker[Recv, Send]) run(ctx context.Context, handler ServerHandler[Recv, Send]) error {
	for {
		log.Ctx(ctx).Trace().Msg("waiting for message")
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
		log.Ctx(ctx).Trace().Msg("passing received message to handler")
		resp, err := handler(msg)
		if err != nil {
			return err
		}
		log.Ctx(ctx).Trace().Msg("sending response message")
		if err := w.sender.sendMsg(ctx, resp); err != nil {
			// TODO : handle this differently
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return err
		}
		log.Ctx(ctx).Trace().Msg("sent response message")
	}
}

func (w *ProtoPipeWorker[Recv, Send]) Close() error {
	receiverCloseErr := w.receiver.Close()
	senderCloseErr := w.sender.Close()
	return errors.Join(receiverCloseErr, senderCloseErr)
}
