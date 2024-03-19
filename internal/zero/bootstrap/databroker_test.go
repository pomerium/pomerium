package bootstrap_test

import (
	"context"
	"errors"
	"testing"

	"github.com/cenkalti/backoff/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pomerium/pomerium/internal/zero/bootstrap"
	"github.com/pomerium/pomerium/pkg/cryptutil"
	"github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/zero/cluster"
)

func TestDatabroker(t *testing.T) {
	src, err := bootstrap.New([]byte("secret"))
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	src.UpdateBootstrap(ctx, cluster.BootstrapConfig{
		SharedSecret: cryptutil.NewKey(),
	})

	errInterrupt := errors.New("quit")
	err = bootstrap.Run(ctx, src,
		func(_ context.Context, _ databroker.DataBrokerServiceClient) error {
			return backoff.Permanent(errInterrupt)
		},
	)
	assert.ErrorIs(t, err, errInterrupt)
}
