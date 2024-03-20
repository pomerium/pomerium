package leaser

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/url"
	"sync"

	"github.com/cenkalti/backoff/v4"
	"google.golang.org/grpc"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/retry"
	"github.com/pomerium/pomerium/internal/zero/bootstrap"
	"github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/grpcutil"
)

// ErrBootstrapConfigurationChanged is returned when the bootstrap configuration has changed and the function needs to be restarted.
var ErrBootstrapConfigurationChanged = errors.New("bootstrap configuration changed")

// Run runs the given function with a databroker client.
// the function would be restarted if the databroker connection has to be re-established.
func Run(
	ctx context.Context,
	source *bootstrap.Source,
	funcs ...func(ctx context.Context, client databroker.DataBrokerServiceClient) error,
) error {
	err := source.WaitReady(ctx)
	if err != nil {
		return fmt.Errorf("waiting for config source to be ready: %w", err)
	}

	p := newRunner(ctx, source)
	defer p.Close()

	b := backoff.NewExponentialBackOff()
	b.MaxElapsedTime = 0
	return backoff.Retry(
		func() error {
			err := p.runOnce(ctx, funcs...)
			if retry.IsTerminalError(err) {
				return backoff.Permanent(err)
			}
			return err
		},
		backoff.WithContext(b, ctx),
	)
}

type runner struct {
	source *bootstrap.Source

	lock      sync.RWMutex
	cancel    chan struct{}
	conn      *grpc.ClientConn
	client    databroker.DataBrokerServiceClient
	initError error
}

func newRunner(ctx context.Context, source *bootstrap.Source) *runner {
	p := &runner{
		source: source,
	}
	p.initLocked(ctx, source.GetConfig())
	source.OnConfigChange(context.Background(), p.onConfigChange)
	return p
}

// Close releases the resources used by the databroker provider.
func (p *runner) Close() {
	p.lock.Lock()
	defer p.lock.Unlock()

	p.closeLocked()
}

// GetDatabrokerClient returns the databroker client and a channel that will be closed when the client is no longer valid.
func (p *runner) getDatabrokerClient() (databroker.DataBrokerServiceClient, <-chan struct{}, error) {
	p.lock.RLock()
	defer p.lock.RUnlock()

	if p.initError != nil {
		return nil, nil, p.initError
	}

	return p.client, p.cancel, nil
}

func (p *runner) onConfigChange(ctx context.Context, cfg *config.Config) {
	p.lock.Lock()
	defer p.lock.Unlock()

	p.closeLocked()
	p.initLocked(ctx, cfg)
}

func (p *runner) initLocked(ctx context.Context, cfg *config.Config) {
	conn, err := newDataBrokerConnection(ctx, cfg)
	if err != nil {
		p.initError = fmt.Errorf("databroker connection: %w", err)
		return
	}

	p.conn = conn
	p.client = databroker.NewDataBrokerServiceClient(conn)
	p.cancel = make(chan struct{})
	p.initError = nil
}

func (p *runner) closeLocked() {
	if p.conn != nil {
		p.conn.Close()
		p.conn = nil
	}
	if p.cancel != nil {
		close(p.cancel)
		p.cancel = nil
	}
	p.initError = errors.New("databroker connection closed")
}

func (p *runner) runOnce(
	ctx context.Context,
	funcs ...func(ctx context.Context, client databroker.DataBrokerServiceClient) error,
) error {
	client, cancelCh, err := p.getDatabrokerClient()
	if err != nil {
		return fmt.Errorf("get databroker client: %w", err)
	}

	ctx, cancel := context.WithCancelCause(ctx)
	defer cancel(context.Canceled)

	go func() {
		select {
		case <-ctx.Done():
		case <-cancelCh:
			cancel(ErrBootstrapConfigurationChanged)
		}
	}()

	return runWithLease(ctx, client, funcs...)
}

func newDataBrokerConnection(ctx context.Context, cfg *config.Config) (*grpc.ClientConn, error) {
	sharedSecret, err := base64.StdEncoding.DecodeString(cfg.Options.SharedKey)
	if err != nil {
		return nil, fmt.Errorf("decode shared_secret: %w", err)
	}
	if len(sharedSecret) != 32 {
		return nil, fmt.Errorf("shared_secret: expected 32 bytes, got %d", len(sharedSecret))
	}

	return grpcutil.NewGRPCClientConn(ctx, &grpcutil.Options{
		Address: &url.URL{
			Scheme: "http",
			Host:   net.JoinHostPort("localhost", cfg.GRPCPort),
		},
		ServiceName:  "databroker",
		SignedJWTKey: sharedSecret,
	})
}
