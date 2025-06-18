package authorize

import (
	"errors"
	"io"

	extensions_ssh "github.com/pomerium/envoy-custom/api/extensions/filters/network/ssh"
	"github.com/pomerium/pomerium/pkg/ssh"
	"github.com/pomerium/pomerium/pkg/storage"
	"golang.org/x/sync/errgroup"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func (a *Authorize) ManageStream(stream extensions_ssh.StreamManagement_ManageStreamServer) error {
	readC := make(chan *extensions_ssh.ClientMessage, 32)
	writeC := make(chan *extensions_ssh.ServerMessage, 32)
	defer close(writeC)

	handler := ssh.StreamHandler{
		WriteC: writeC,
		ReadC:  readC,
	}

	eg, ctx := errgroup.WithContext(stream.Context())
	querier := storage.NewCachingQuerier(
		storage.NewQuerier(a.state.Load().dataBrokerClient),
		storage.GlobalCache,
	)
	ctx = storage.WithQuerier(ctx, querier)

	eg.Go(func() error {
		defer close(readC)
		for {
			req, err := stream.Recv()
			if err != nil {
				if errors.Is(err, io.EOF) {
					return nil
				}
				return err
			}
			readC <- req
		}
	})

	eg.Go(func() error {
		for {
			select {
			case <-ctx.Done():
				return nil
			case msg := <-writeC:
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

func (a *Authorize) ServeChannel(extensions_ssh.StreamManagement_ServeChannelServer) error {
	return status.Errorf(codes.Unimplemented, "method ServeChannel not implemented")
}
