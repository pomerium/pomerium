package grpcutil

import (
	"context"
	"errors"
	"io"
	"slices"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
)

const forwarderMetadataKey = "pomerium-forwarder-id"

// A Forwarder forwards gRPC requests from one server to another.
type Forwarder interface {
	Forward(ctx context.Context, fn func(ctx context.Context) error) error
}

type forwarder struct {
	id string
}

// NewForwarder creates a new Forwarder.
func NewForwarder() Forwarder {
	return &forwarder{
		id: uuid.New().String(),
	}
}

// Forward forwards metadata from an incoming request to an outgoing request.
// Each forwarder has a unique id to detect forwarding cycles.
func (f *forwarder) Forward(ctx context.Context, fn func(ctx context.Context) error) error {
	if slices.Contains(metadata.ValueFromIncomingContext(ctx, forwarderMetadataKey), f.id) {
		return ErrForwardingCycleDetected
	}
	if callInfo, ok := connect.CallInfoForHandlerContext(ctx); ok && callInfo.RequestHeader().Get(forwarderMetadataKey) == f.id {
		return ErrForwardingCycleDetected
	}

	if inMD, ok := metadata.FromIncomingContext(ctx); ok {
		outMD, ok := metadata.FromOutgoingContext(ctx)
		if !ok {
			outMD = make(metadata.MD)
		}
		for k, vs := range inMD {
			outMD.Append(k, vs...)
		}
		ctx = metadata.NewOutgoingContext(ctx, outMD)

		var callInfo connect.CallInfo
		ctx, callInfo = connect.NewClientContext(ctx)
		for k, vs := range inMD {
			for _, v := range vs {
				callInfo.RequestHeader().Add(k, v)
			}
		}
		callInfo.RequestHeader().Set(forwarderMetadataKey, f.id)
	}

	ctx = metadata.AppendToOutgoingContext(ctx, forwarderMetadataKey, f.id)

	return fn(ctx)
}

// ForwardStream takes a client stream and copies it to a server stream.
func ForwardStream[Res any, Req any](
	forwarder Forwarder,
	serverStream grpc.ServerStreamingServer[Res],
	getClientStream func(ctx context.Context, req Req, opts ...grpc.CallOption) (grpc.ServerStreamingClient[Res], error),
	req Req,
	opts ...grpc.CallOption,
) error {
	return forwarder.Forward(serverStream.Context(), func(ctx context.Context) error {
		ctx, cancel := context.WithCancel(ctx)
		defer cancel()

		clientStream, err := getClientStream(ctx, req, opts...)
		if err != nil {
			return err
		}

		for {
			msg, err := clientStream.Recv()
			if errors.Is(err, io.EOF) {
				return nil
			} else if err != nil {
				return err
			}

			err = serverStream.Send(msg)
			if err != nil {
				return err
			}
		}
	})
}

// ForwardUnary forwards a unary request to a gRPC client.
func ForwardUnary[Res any, Req any](
	ctx context.Context,
	forwarder Forwarder,
	fn func(ctx context.Context, req Req, opts ...grpc.CallOption) (Res, error),
	req Req,
	opts ...grpc.CallOption,
) (res Res, err error) {
	return res, forwarder.Forward(ctx, func(ctx context.Context) error {
		var err error
		res, err = fn(ctx, req, opts...)
		return err
	})
}
