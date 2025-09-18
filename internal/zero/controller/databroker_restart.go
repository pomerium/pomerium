package controller

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
	"sync"

	"google.golang.org/grpc"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/retry"
	"github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/grpcutil"
)

// ErrBootstrapConfigurationChanged is returned when the bootstrap configuration has changed and the function needs to be restarted.
var ErrBootstrapConfigurationChanged = errors.New("bootstrap configuration changed")

type DatabrokerRestartRunner struct {
	lock      sync.RWMutex
	cancel    chan struct{}
	conn      *grpc.ClientConn
	client    databroker.DataBrokerServiceClient
	initError error
}

// NewDatabrokerRestartRunner is a helper to run a function that needs to be restarted when the underlying databroker configuration changes.
func NewDatabrokerRestartRunner(
	ctx context.Context,
	src config.Source,
) *DatabrokerRestartRunner {
	p := new(DatabrokerRestartRunner)
	p.initLocked(ctx, src.GetConfig())
	src.OnConfigChange(ctx, p.onConfigChange)
	return p
}

func (p *DatabrokerRestartRunner) Run(
	ctx context.Context,
	fn func(context.Context, databroker.DataBrokerServiceClient) error,
) error {
	return retry.WithBackoff(ctx, "databroker-restart", func(ctx context.Context) error { return p.runUntilDatabrokerChanges(ctx, fn) })
}

// Close releases the resources used by the databroker provider.
func (p *DatabrokerRestartRunner) Close() {
	p.lock.Lock()
	defer p.lock.Unlock()

	p.closeLocked()
}

func (p *DatabrokerRestartRunner) GetDatabrokerClient() (databroker.DataBrokerServiceClient, error) {
	client, _, err := p.getDatabrokerClient()
	return client, err
}

// GetDatabrokerClient returns the databroker client and a channel that will be closed when the client is no longer valid.
func (p *DatabrokerRestartRunner) getDatabrokerClient() (databroker.DataBrokerServiceClient, <-chan struct{}, error) {
	p.lock.RLock()
	defer p.lock.RUnlock()

	if p.initError != nil {
		return nil, nil, p.initError
	}

	return p.client, p.cancel, nil
}

func (p *DatabrokerRestartRunner) onConfigChange(ctx context.Context, cfg *config.Config) {
	p.lock.Lock()
	defer p.lock.Unlock()

	p.closeLocked()
	p.initLocked(ctx, cfg)
}

func (p *DatabrokerRestartRunner) initLocked(ctx context.Context, cfg *config.Config) {
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

func (p *DatabrokerRestartRunner) closeLocked() {
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

func (p *DatabrokerRestartRunner) runUntilDatabrokerChanges(
	ctx context.Context,
	fn func(context.Context, databroker.DataBrokerServiceClient) error,
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

	return fn(ctx, client)
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
			Host:   cfg.GRPCAddress.String(),
		},
		ServiceName:  "databroker",
		SignedJWTKey: sharedSecret,
	})
}
