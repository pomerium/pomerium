package ipc

import (
	"bufio"
	"errors"
	"os"
	"reflect"
	"sync"
	"sync/atomic"
	"time"

	"google.golang.org/protobuf/encoding/protodelim"
	"google.golang.org/protobuf/proto"
)

const serviceName = "pipe-ipc"

// PipePair encapsulates the read/write ends of a pipe.
type PipePair struct {
	Read  *os.File
	Write *os.File

	closeF func() error
}

// ProtoPipeReceiver receives length-delimited protobuf messages from the read
// end of a PipePair.
type ProtoPipeReceiver[Recv proto.Message] struct {
	*PipePair
	rd             protodelim.Reader
	shouldShutdown atomic.Bool
}

// ProtoPipeSender sends length-delimited protobuf messages to the write end of
// a PipePair.
type ProtoPipeSender[Send proto.Message] struct {
	*PipePair
}

// ProtoPipeWorker handles bi-directional communication between receivers and senders.
type ProtoPipeWorker[Recv proto.Message, Send proto.Message] struct {
	receiver *ProtoPipeReceiver[Recv]
	sender   *ProtoPipeSender[Send]
}

// ServerHandler runs application logic processing the Recv proto into Send proto
type ServerHandler[Recv proto.Message, Send proto.Message] = func(Recv) (Send, error)

type ServerOptions struct {
	ShutdownTimeout time.Duration
	// Name is used for telemetry
	Name string
}

// ProtoPipeServer handles a bidirectional streaming server implementation for [req,resp] proto pairs
// on top of unix pipe transports.
// It is meant to be long-lived and the underlying workers can be swapped out for
// new-ones on demand.
type ProtoPipeServer[Recv proto.Message, Send proto.Message] struct {
	workers []*ProtoPipeWorker[Recv, Send]

	updateC chan []*ProtoPipeWorker[Recv, Send]

	handler ServerHandler[Recv, Send]

	serveC chan error
	ServerOptions
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

func NewProtoPipeReceiver[Recv proto.Message](pair *PipePair) *ProtoPipeReceiver[Recv] {
	return &ProtoPipeReceiver[Recv]{
		PipePair: pair,
		rd:       bufio.NewReader(pair.Read),
	}
}

func NewProtoPipeSender[Send proto.Message](pair *PipePair) *ProtoPipeSender[Send] {
	return &ProtoPipeSender[Send]{PipePair: pair}
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

func NewProtoPipeServer[Recv proto.Message, Send proto.Message](
	workers []*ProtoPipeWorker[Recv, Send],
	handler ServerHandler[Recv, Send],
	options ServerOptions,
) *ProtoPipeServer[Recv, Send] {
	return &ProtoPipeServer[Recv, Send]{
		workers:       workers,
		updateC:       make(chan []*ProtoPipeWorker[Recv, Send], 8),
		handler:       handler,
		serveC:        make(chan error, 1),
		ServerOptions: options,
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
