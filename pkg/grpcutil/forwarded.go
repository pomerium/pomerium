package grpcutil

import (
	"context"

	"google.golang.org/grpc/metadata"
)

const DisableClusterForwardingKey = "pomerium-disable-cluster-forwarding"

func DisableClusterForwardingFromIncoming(ctx context.Context) (disabled bool) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return false
	}
	return len(md.Get(DisableClusterForwardingKey)) > 0
}

func WithOutgoingDisableClusterForwarding(ctx context.Context) context.Context {
	md, ok := metadata.FromOutgoingContext(ctx)
	if !ok {
		md = make(metadata.MD)
	}
	md.Set(DisableClusterForwardingKey, "1")
	return metadata.NewOutgoingContext(ctx, md)
}

const ForwardedForKey = "pomerium-forwarded-for"

func ForwardedForFromIncoming(ctx context.Context) []string {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return nil
	}
	return md.Get(ForwardedForKey)
}

func WithOutgoingForwardedFor(ctx context.Context, forwardedFor []string) context.Context {
	md, ok := metadata.FromOutgoingContext(ctx)
	if !ok {
		md = make(metadata.MD)
	}
	md.Set(ForwardedForKey, forwardedFor...)
	return metadata.NewOutgoingContext(ctx, md)
}
