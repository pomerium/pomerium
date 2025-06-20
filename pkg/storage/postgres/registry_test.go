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
	"github.com/pomerium/pomerium/pkg/protoutil"
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
	t.Parallel()

	if os.Getenv("GITHUB_ACTION") != "" && runtime.GOOS == "darwin" {
		t.Skip("Github action can not run docker on MacOS")
	}

	ctx, clearTimeout := context.WithTimeout(t.Context(), maxWait)
	defer clearTimeout()

	testutil.WithTestPostgres(t, func(dsn string) {
		backend := New(ctx, dsn)
		defer backend.Close()

		eg, ctx := errgroup.WithContext(ctx)
		listResults := make(chan *registry.ServiceList)
		eg.Go(func() error {
			srv := mockRegistryWatchServer{
				context: ctx,
				send: func(res *registry.ServiceList) error {
					select {
					case <-ctx.Done():
						return context.Cause(ctx)
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
				return context.Cause(ctx)
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
				return context.Cause(ctx)
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
	})
}

func TestUnmarshalJSONUnknownFields(t *testing.T) {
	data, err := protoutil.UnmarshalAnyJSON([]byte(`
	{
		"@type": "type.googleapis.com/registry.Service",
		"kind": "AUTHENTICATE",
		"endpoint": "endpoint",
		"unknown_field": true
	  }
	`))
	require.NoError(t, err)
	var val registry.Service
	require.NoError(t, data.UnmarshalTo(&val))
	assert.Equal(t, registry.ServiceKind_AUTHENTICATE, val.Kind)
	assert.Equal(t, "endpoint", val.Endpoint)
}
