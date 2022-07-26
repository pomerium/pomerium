package postgres

import (
	"context"
	"errors"
	"fmt"
	"os"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sync/errgroup"

	"github.com/pomerium/pomerium/internal/testutil"
	"github.com/pomerium/pomerium/pkg/grpc/registry"
)

type mockRegistryWatchServer struct {
	registry.Registry_WatchServer
	context context.Context
	send    func(*registry.ServiceList) error
}

func (m mockRegistryWatchServer) Context() context.Context {
	return m.context
}

func (m mockRegistryWatchServer) Send(res *registry.ServiceList) error {
	return m.send(res)
}

func TestRegistry(t *testing.T) {
	if os.Getenv("GITHUB_ACTION") != "" && runtime.GOOS == "darwin" {
		t.Skip("Github action can not run docker on MacOS")
	}

	t.Parallel()

	ctx, clearTimeout := context.WithTimeout(context.Background(), maxWait)
	defer clearTimeout()

	require.NoError(t, testutil.WithTestPostgres(func(dsn string) error {
		backend := New(dsn)
		defer backend.Close()

		eg, ctx := errgroup.WithContext(ctx)
		listResults := make(chan *registry.ServiceList)
		eg.Go(func() error {
			srv := mockRegistryWatchServer{
				context: ctx,
				send: func(res *registry.ServiceList) error {
					select {
					case <-ctx.Done():
						return ctx.Err()
					case listResults <- res:
					}
					return nil
				},
			}
			err := backend.RegistryServer().Watch(&registry.ListRequest{
				Kinds: []registry.ServiceKind{
					registry.ServiceKind_AUTHENTICATE,
					registry.ServiceKind_CONSOLE,
				},
			}, srv)
			if errors.Is(err, context.Canceled) {
				return nil
			}
			return err
		})
		eg.Go(func() error {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case res := <-listResults:
				testutil.AssertProtoEqual(t, &registry.ServiceList{}, res)
			}

			res, err := backend.RegistryServer().Report(ctx, &registry.RegisterRequest{
				Services: []*registry.Service{
					{Kind: registry.ServiceKind_AUTHENTICATE, Endpoint: "authenticate.example.com"},
					{Kind: registry.ServiceKind_AUTHORIZE, Endpoint: "authorize.example.com"},
					{Kind: registry.ServiceKind_CONSOLE, Endpoint: "console.example.com"},
				},
			})
			if err != nil {
				return fmt.Errorf("error reporting status: %w", err)
			}
			assert.NotEqual(t, 0, res.GetCallBackAfter())

			select {
			case <-ctx.Done():
				return ctx.Err()
			case res := <-listResults:
				testutil.AssertProtoEqual(t, &registry.ServiceList{
					Services: []*registry.Service{
						{Kind: registry.ServiceKind_AUTHENTICATE, Endpoint: "authenticate.example.com"},
						{Kind: registry.ServiceKind_CONSOLE, Endpoint: "console.example.com"},
					},
				}, res)
			}

			return context.Canceled
		})
		err := eg.Wait()
		if errors.Is(err, context.Canceled) {
			err = nil
		}
		assert.NoError(t, err)

		return nil
	}))
}
