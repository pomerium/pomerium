package redis

import (
	"context"
	"net"
	"os"
	"runtime"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sync/errgroup"
	"google.golang.org/grpc"

	"github.com/pomerium/pomerium/internal/testutil"
	registrypb "github.com/pomerium/pomerium/pkg/grpc/registry"
)

func TestReport(t *testing.T) {
	if os.Getenv("GITHUB_ACTION") != "" && runtime.GOOS == "darwin" {
		t.Skip("Github action can not run docker on MacOS")
	}

	ctx := context.Background()
	require.NoError(t, testutil.WithTestRedis(false, func(rawURL string) error {
		tm := time.Now()

		i, err := New(rawURL,
			WithGetNow(func() time.Time {
				return tm
			}),
			WithTTL(time.Second*10))
		require.NoError(t, err)
		defer func() { _ = i.Close() }()

		_, err = i.Report(ctx, &registrypb.RegisterRequest{
			Services: []*registrypb.Service{
				{Kind: registrypb.ServiceKind_AUTHORIZE, Endpoint: "https://authorize.example.com"},
				{Kind: registrypb.ServiceKind_AUTHENTICATE, Endpoint: "https://authenticate.example.com"},
				{Kind: registrypb.ServiceKind_PROXY, Endpoint: "https://proxy.example.com"},
			},
		})
		require.NoError(t, err)

		// move forward 5 seconds
		tm = tm.Add(time.Second * 5)
		_, err = i.Report(ctx, &registrypb.RegisterRequest{
			Services: []*registrypb.Service{
				{Kind: registrypb.ServiceKind_AUTHENTICATE, Endpoint: "https://authenticate.example.com"},
				{Kind: registrypb.ServiceKind_PROXY, Endpoint: "https://proxy.example.com"},
			},
		})
		require.NoError(t, err)

		lst, err := i.List(ctx, &registrypb.ListRequest{
			Kinds: []registrypb.ServiceKind{
				registrypb.ServiceKind_AUTHORIZE,
				registrypb.ServiceKind_PROXY,
			},
		})
		require.NoError(t, err)
		assert.Equal(t, []*registrypb.Service{
			{Kind: registrypb.ServiceKind_AUTHORIZE, Endpoint: "https://authorize.example.com"},
			{Kind: registrypb.ServiceKind_PROXY, Endpoint: "https://proxy.example.com"},
		}, lst.GetServices(), "should list selected services")

		// move forward 6 seconds
		tm = tm.Add(time.Second * 6)
		lst, err = i.List(ctx, &registrypb.ListRequest{
			Kinds: []registrypb.ServiceKind{
				registrypb.ServiceKind_AUTHORIZE,
				registrypb.ServiceKind_PROXY,
			},
		})
		require.NoError(t, err)
		assert.Equal(t, []*registrypb.Service{
			{Kind: registrypb.ServiceKind_PROXY, Endpoint: "https://proxy.example.com"},
		}, lst.GetServices(), "should expire old services")

		return nil
	}))
}

func TestWatch(t *testing.T) {
	if os.Getenv("GITHUB_ACTION") != "" && runtime.GOOS == "darwin" {
		t.Skip("Github action can not run docker on MacOS")
	}

	require.NoError(t, testutil.WithTestRedis(false, func(rawURL string) error {
		ctx, clearTimeout := context.WithTimeout(context.Background(), time.Second*15)
		defer clearTimeout()

		ctx, cancel := context.WithCancel(ctx)
		defer cancel()

		tm := time.Now()
		i, err := New(rawURL,
			WithGetNow(func() time.Time {
				return tm
			}),
			WithTTL(time.Second*10))
		require.NoError(t, err)

		li, err := net.Listen("tcp", "127.0.0.1:0")
		require.NoError(t, err)
		defer li.Close()

		srv := grpc.NewServer()
		registrypb.RegisterRegistryServer(srv, i)
		eg, ctx := errgroup.WithContext(ctx)
		eg.Go(func() error {
			<-ctx.Done()
			srv.Stop()
			return nil
		})
		eg.Go(func() error {
			return srv.Serve(li)
		})
		eg.Go(func() error {
			defer cancel()

			cc, err := grpc.Dial(li.Addr().String(), grpc.WithInsecure())
			if err != nil {
				return err
			}

			client := registrypb.NewRegistryClient(cc)

			// store the initial services
			_, err = client.Report(ctx, &registrypb.RegisterRequest{
				Services: []*registrypb.Service{
					{Kind: registrypb.ServiceKind_AUTHENTICATE, Endpoint: "http://authenticate1.example.com"},
					{Kind: registrypb.ServiceKind_AUTHORIZE, Endpoint: "http://authorize2.example.com"},
					{Kind: registrypb.ServiceKind_AUTHORIZE, Endpoint: "http://authorize1.example.com"},
				},
			})
			if err != nil {
				return err
			}

			stream, err := client.Watch(ctx, &registrypb.ListRequest{
				Kinds: []registrypb.ServiceKind{
					registrypb.ServiceKind_AUTHORIZE,
				},
			})
			if err != nil {
				return err
			}
			defer func() { _ = stream.CloseSend() }()

			lst, err := stream.Recv()
			if err != nil {
				return err
			}
			assert.Equal(t, []*registrypb.Service{
				{Kind: registrypb.ServiceKind_AUTHORIZE, Endpoint: "http://authorize1.example.com"},
				{Kind: registrypb.ServiceKind_AUTHORIZE, Endpoint: "http://authorize2.example.com"},
			}, lst.GetServices())

			// update authenticate
			_, err = client.Report(ctx, &registrypb.RegisterRequest{
				Services: []*registrypb.Service{
					{Kind: registrypb.ServiceKind_AUTHENTICATE, Endpoint: "http://authenticate1.example.com"},
				},
			})
			if err != nil {
				return err
			}

			// add an authorize
			_, err = client.Report(ctx, &registrypb.RegisterRequest{
				Services: []*registrypb.Service{
					{Kind: registrypb.ServiceKind_AUTHORIZE, Endpoint: "http://authorize3.example.com"},
				},
			})
			if err != nil {
				return err
			}

			lst, err = stream.Recv()
			if err != nil {
				return err
			}
			assert.Equal(t, []*registrypb.Service{
				{Kind: registrypb.ServiceKind_AUTHORIZE, Endpoint: "http://authorize1.example.com"},
				{Kind: registrypb.ServiceKind_AUTHORIZE, Endpoint: "http://authorize2.example.com"},
				{Kind: registrypb.ServiceKind_AUTHORIZE, Endpoint: "http://authorize3.example.com"},
			}, lst.GetServices())

			return nil
		})
		require.NoError(t, eg.Wait())
		return nil
	}))
}
