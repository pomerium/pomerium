package databroker

import (
	"context"
	"sync/atomic"

	"google.golang.org/grpc"
)

// A CacheInvalidator has interceptors that can be used to clear the cache when
// the server version changes.
type CacheInvalidator struct {
	StreamClientInterceptor grpc.StreamClientInterceptor
	UnaryClientInterceptor  grpc.UnaryClientInterceptor
}

type clientStreamRecvMsgWrapper struct {
	grpc.ClientStream
	recvMsg func(m any) error
}

func (s clientStreamRecvMsgWrapper) RecvMsg(m any) error {
	return s.recvMsg(m)
}

// NewCacheInvalidator creates a new CacheInvalidator.
func NewCacheInvalidator(cache interface{ InvalidateAll() }) *CacheInvalidator {
	var currentServerVersion atomic.Uint64
	maybeInvalidate := func(m any) {
		if obj, ok := m.(interface{ GetVersions() *Versions }); ok && obj.GetVersions() != nil {
			m = obj.GetVersions()
		}
		if obj, ok := m.(interface{ GetServerVersion() uint64 }); ok && obj.GetServerVersion() > 0 {
			nv := obj.GetServerVersion()
			ov := currentServerVersion.Swap(nv)
			if ov > 0 && ov != nv {
				cache.InvalidateAll()
			}
		}
	}

	return &CacheInvalidator{
		StreamClientInterceptor: func(ctx context.Context, desc *grpc.StreamDesc, cc *grpc.ClientConn, method string, streamer grpc.Streamer, opts ...grpc.CallOption) (grpc.ClientStream, error) {
			stream, err := streamer(ctx, desc, cc, method, opts...)
			if err != nil {
				return nil, err
			}
			return clientStreamRecvMsgWrapper{
				ClientStream: stream,
				recvMsg: func(m any) error {
					err := stream.RecvMsg(m)
					maybeInvalidate(m)
					return err
				},
			}, err
		},
		UnaryClientInterceptor: func(ctx context.Context, method string, req, reply any, cc *grpc.ClientConn, invoker grpc.UnaryInvoker, opts ...grpc.CallOption) error {
			err := invoker(ctx, method, req, reply, cc, opts...)
			maybeInvalidate(reply)
			return err
		},
	}
}
