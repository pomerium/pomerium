// Package mux provides the way to listen for updates from the cloud
package mux

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sync/atomic"

	"github.com/cenkalti/backoff/v4"
	"github.com/rs/zerolog/log"

	"github.com/pomerium/pomerium/internal/version"
	"github.com/pomerium/pomerium/internal/zero/apierror"
	"github.com/pomerium/pomerium/pkg/fanout"
	"github.com/pomerium/pomerium/pkg/health"
	"github.com/pomerium/pomerium/pkg/zero/connect"
)

// Mux is the service that listens for updates from the cloud
type Mux struct {
	client connect.ConnectClient
	mux    *fanout.FanOut[message]

	ready chan struct{}

	connected atomic.Bool
}

// New creates a new mux service that listens for updates from the cloud
func New(client connect.ConnectClient) *Mux {
	svc := &Mux{
		client: client,
		ready:  make(chan struct{}),
	}
	return svc
}

// Run starts the service
func (svc *Mux) Run(ctx context.Context, opts ...fanout.Option) error {
	ctx, cancel := context.WithCancelCause(ctx)
	defer func() { cancel(ctx.Err()) }()

	svc.mux = fanout.Start[message](ctx, opts...)
	close(svc.ready)

	err := svc.run(ctx)
	if err != nil {
		cancel(err)
		return err
	}
	return nil
}

func (svc *Mux) run(ctx context.Context) error {
	b := backoff.NewExponentialBackOff()
	b.MaxElapsedTime = 0

	return backoff.Retry(func() error {
		err := svc.subscribeAndDispatch(ctx, b.Reset)
		health.ReportError(health.ZeroConnect, err)
		if apierror.IsTerminalError(err) {
			return backoff.Permanent(err)
		}
		return err
	}, backoff.WithContext(b, ctx))
}

func (svc *Mux) subscribeAndDispatch(ctx context.Context, onConnected func()) (err error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	hostname, err := os.Hostname()
	if err != nil {
		hostname = "__unknown__"
	}
	stream, err := svc.client.Subscribe(ctx, &connect.SubscribeRequest{
		Hostname: hostname,
		Version:  version.FullVersion(),
	})
	if err != nil {
		return fmt.Errorf("subscribe: %w", err)
	}
	health.ReportRunning(health.ZeroConnect)
	onConnected()

	if err = svc.onConnected(ctx); err != nil {
		return fmt.Errorf("onConnected: %w", err)
	}
	defer func() {
		err = errors.Join(err, svc.onDisconnected(ctx))
	}()

	log.Ctx(ctx).Debug().Msg("subscribed to connect service")
	for {
		msg, err := stream.Recv()
		log.Ctx(ctx).Debug().Interface("msg", msg).Err(err).Msg("receive")
		if err != nil {
			return fmt.Errorf("receive: %w", err)
		}
		err = svc.onMessage(ctx, msg)
		if err != nil {
			return fmt.Errorf("onMessage: %w", err)
		}
	}
}
