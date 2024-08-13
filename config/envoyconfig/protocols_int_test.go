package envoyconfig_test

import (
	"context"
	"fmt"
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/interop"
	"google.golang.org/grpc/interop/grpc_testing"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/pkg/cmd/pomerium"
	"github.com/pomerium/pomerium/pkg/netutil"
)

func TestH2C(t *testing.T) {
	if testing.Short() {
		t.SkipNow()
	}

	ctx, ca := context.WithCancel(context.Background())

	opts := config.NewDefaultOptions()
	listener, err := (&net.ListenConfig{}).Listen(ctx, "tcp", "127.0.0.1:0")
	require.NoError(t, err)
	ports, err := netutil.AllocatePorts(7)
	require.NoError(t, err)
	urls, err := config.ParseWeightedUrls("http://"+listener.Addr().String(), "h2c://"+listener.Addr().String())
	require.NoError(t, err)
	opts.Addr = fmt.Sprintf("127.0.0.1:%s", ports[0])
	opts.Routes = []config.Policy{
		{
			From:                             fmt.Sprintf("https://grpc-http.localhost.pomerium.io:%s", ports[0]),
			To:                               urls[:1],
			AllowPublicUnauthenticatedAccess: true,
		},
		{
			From:                             fmt.Sprintf("https://grpc-h2c.localhost.pomerium.io:%s", ports[0]),
			To:                               urls[1:],
			AllowPublicUnauthenticatedAccess: true,
		},
	}
	opts.CertFile = "../../integration/tpl/files/trusted.pem"
	opts.KeyFile = "../../integration/tpl/files/trusted-key.pem"
	cfg := &config.Config{Options: opts}
	cfg.AllocatePorts(*(*[6]string)(ports[1:]))

	server := grpc.NewServer(grpc.Creds(insecure.NewCredentials()))
	grpc_testing.RegisterTestServiceServer(server, interop.NewTestServer())
	go server.Serve(listener)

	errC := make(chan error, 1)
	go func() {
		errC <- pomerium.Run(ctx, config.NewStaticSource(cfg))
	}()

	t.Cleanup(func() {
		ca()
		assert.ErrorIs(t, context.Canceled, <-errC)
	})

	tlsConfig, err := credentials.NewClientTLSFromFile("../../integration/tpl/files/ca.pem", "")
	require.NoError(t, err)

	t.Run("h2c", func(t *testing.T) {
		t.Parallel()

		cc, err := grpc.Dial(fmt.Sprintf("grpc-h2c.localhost.pomerium.io:%s", ports[0]), grpc.WithTransportCredentials(tlsConfig))
		require.NoError(t, err)
		client := grpc_testing.NewTestServiceClient(cc)
		var md metadata.MD
		_, err = client.EmptyCall(ctx, &grpc_testing.Empty{}, grpc.WaitForReady(true), grpc.Header(&md))
		cc.Close()
		assert.NoError(t, err)
		assert.Contains(t, md, "x-envoy-upstream-service-time")
	})
	t.Run("http", func(t *testing.T) {
		t.Parallel()

		cc, err := grpc.Dial(fmt.Sprintf("grpc-http.localhost.pomerium.io:%s", ports[0]), grpc.WithTransportCredentials(tlsConfig))
		require.NoError(t, err)
		client := grpc_testing.NewTestServiceClient(cc)
		var md metadata.MD
		_, err = client.EmptyCall(ctx, &grpc_testing.Empty{}, grpc.WaitForReady(true), grpc.Trailer(&md))
		cc.Close()
		stat := status.Convert(err)
		assert.NotNil(t, stat)
		assert.Equal(t, stat.Code(), codes.Unavailable)
		assert.NotContains(t, md, "x-envoy-upstream-service-time")
		assert.Contains(t, stat.Message(), "<!DOCTYPE html>")
		assert.Contains(t, stat.Message(), "upstream_reset_before_response_started{protocol_error}")
	})
}
