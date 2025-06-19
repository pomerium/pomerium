package authorize

import (
	"errors"
	"io"
	"strconv"

	extensions_ssh "github.com/pomerium/envoy-custom/api/extensions/filters/network/ssh"
	"github.com/pomerium/pomerium/pkg/storage"
	"golang.org/x/sync/errgroup"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func (a *Authorize) ManageStream(stream extensions_ssh.StreamManagement_ManageStreamServer) error {
	event, err := stream.Recv()
	if err != nil {
		return err
	}
	// first message should be a downstream connected event
	var streamID uint64
	if dc := event.GetEvent().GetDownstreamConnected(); dc != nil {
		streamID = dc.StreamId
	} else {
		return status.Errorf(codes.Internal, "first message was not a downstream connected event")
	}
	handler := a.state.Load().ssh.NewStreamHandler(streamID)
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
		idStr := md.GetFilterMetadata()["pomerium"].GetFields()["stream-id"].GetStringValue()
		if idStr == "" {
			return status.Errorf(codes.Internal, "no stream id found in metadata")
		}
		id, err := strconv.ParseUint(idStr, 10, 64)
		if err != nil {
			return status.Errorf(codes.Internal, "invalid stream id found in metadata: %v", err)
		}
		streamID = id
	} else {
		return status.Errorf(codes.Internal, "first message was not metadata")
	}
	handler := a.state.Load().ssh.LookupStream(streamID)
	if handler == nil {
		return status.Errorf(codes.InvalidArgument, "stream not found")
	}

	return handler.ServeChannel(stream)
}
