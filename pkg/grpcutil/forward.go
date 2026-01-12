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
	headers := map[string][]string{}

	// retrieve any request headers from gRPC or connect
	if inMD, ok := metadata.FromIncomingContext(ctx); ok {
		if slices.Contains(metadata.ValueFromIncomingContext(ctx, forwarderMetadataKey), f.id) {
			return ErrForwardingCycleDetected
		}
		for k, vs := range inMD {
			headers[k] = append(headers[k], vs...)
		}
	}
	if ci, ok := connect.CallInfoForHandlerContext(ctx); ok {
		if ci.RequestHeader().Get(forwarderMetadataKey) == f.id {
			return ErrForwardingCycleDetected
		}
		for k, vs := range ci.RequestHeader() {
			headers[k] = append(headers[k], vs...)
		}
	}

	// add the fowarding metadata header
	headers[forwarderMetadataKey] = []string{f.id}

	// add the new request headers to the outgoing client context
	outMD, ok := metadata.FromOutgoingContext(ctx)
	if !ok {
		outMD = make(metadata.MD)
	}
	for k, vs := range headers {
		outMD.Append(k, vs...)
	}
	ctx = metadata.NewOutgoingContext(ctx, outMD)

	ctx, ci := connect.NewClientContext(ctx)
	for k, vs := range headers {
		ci.RequestHeader()[k] = append(ci.RequestHeader()[k], vs...)
	}

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
