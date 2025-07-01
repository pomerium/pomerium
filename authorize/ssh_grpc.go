package authorize

import (
	"errors"
	"io"

	"golang.org/x/sync/errgroup"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	extensions_ssh "github.com/pomerium/envoy-custom/api/extensions/filters/network/ssh"
	"github.com/pomerium/pomerium/pkg/storage"
)

func (a *Authorize) ManageStream(stream extensions_ssh.StreamManagement_ManageStreamServer) error {
	event, err := stream.Recv()
	if err != nil {
		return err
	}
	// first message should be a downstream connected event
	downstream := event.GetEvent().GetDownstreamConnected()
	if downstream == nil {
		return status.Errorf(codes.Internal, "first message was not a downstream connected event")
	}
	handler := a.state.Load().ssh.NewStreamHandler(a.currentConfig.Load(), downstream)
	defer handler.Close()

	eg, ctx := errgroup.WithContext(stream.Context())
	querier := storage.NewCachingQuerier(
		storage.NewQuerier(a.state.Load().dataBrokerClient),
		storage.GlobalCache,
	)
	ctx = storage.WithQuerier(ctx, querier)

	eg.Go(func() error {
		for {
			req, err := stream.Recv()
			if err != nil {
				if errors.Is(err, io.EOF) {
					return nil
				}
				return err
			}
			handler.ReadC() <- req
		}
	})

	eg.Go(func() error {
		for {
			select {
			case <-ctx.Done():
				return nil
			case msg := <-handler.WriteC():
				if err := stream.Send(msg); err != nil {
					if errors.Is(err, io.EOF) {
						return nil
					}
					return err
				}
			}
		}
	})

	return handler.Run(ctx)
}

func (a *Authorize) ServeChannel(stream extensions_ssh.StreamManagement_ServeChannelServer) error {
	metadata, err := stream.Recv()
	if err != nil {
		return err
	}
	// first message contains metadata
	var streamID uint64
	if md := metadata.GetMetadata(); md != nil {
		var typedMd extensions_ssh.FilterMetadata
		if err := md.GetTypedFilterMetadata()["com.pomerium.ssh"].UnmarshalTo(&typedMd); err != nil {
			return err
		}
		streamID = typedMd.StreamId
	} else {
		return status.Errorf(codes.Internal, "first message was not metadata")
	}
	handler := a.state.Load().ssh.LookupStream(streamID)
	if handler == nil || !handler.IsExpectingInternalChannel() {
		return status.Errorf(codes.InvalidArgument, "stream not found")
	}

	return handler.ServeChannel(stream)
}
