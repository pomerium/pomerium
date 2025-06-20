package controller_test

import (
	"context"
	"encoding/base64"
	"errors"
	"testing"

	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/zero/controller"
	"github.com/pomerium/pomerium/pkg/cryptutil"
	"github.com/pomerium/pomerium/pkg/grpc/databroker"
)

type mockConfigSource struct {
	mock.Mock
	config.Source
}

func (s *mockConfigSource) GetConfig() *config.Config {
	args := s.Called()
	return args.Get(0).(*config.Config)
}

func (s *mockConfigSource) OnConfigChange(ctx context.Context, cl config.ChangeListener) {
	s.Called(ctx, cl)
}

func TestDatabrokerRestart(t *testing.T) {
	t.Parallel()

	newConfig := func() *config.Config {
		return &config.Config{
			Options: &config.Options{
				SharedKey: base64.StdEncoding.EncodeToString(cryptutil.NewKey()),
			},
			GRPCPort: ":12345",
		}
	}

	t.Run("no error", func(t *testing.T) {
		t.Parallel()

		src := new(mockConfigSource)
		src.On("OnConfigChange", mock.Anything, mock.Anything).Once()
		src.On("GetConfig").Once().Return(newConfig())

		ctx := t.Context()
		r := controller.NewDatabrokerRestartRunner(ctx, src)
		defer r.Close()

		err := r.Run(ctx, func(_ context.Context, _ databroker.DataBrokerServiceClient) error {
			return nil
		})
		require.NoError(t, err)
	})
	t.Run("error, retry", func(t *testing.T) {
		t.Parallel()

		src := new(mockConfigSource)
		src.On("OnConfigChange", mock.Anything, mock.Anything).Once()
		src.On("GetConfig").Once().Return(newConfig())

		ctx := t.Context()
		r := controller.NewDatabrokerRestartRunner(ctx, src)
		defer r.Close()

		count := 0
		err := r.Run(ctx, func(_ context.Context, _ databroker.DataBrokerServiceClient) error {
			count++
			if count == 1 {
				return errors.New("simulated error")
			}
			return nil
		})
		require.NoError(t, err)
		require.Equal(t, 2, count)
	})
	t.Run("config changed, execution restarted", func(t *testing.T) {
		t.Parallel()

		src := new(mockConfigSource)
		var cl config.ChangeListener
		src.On("OnConfigChange", mock.Anything, mock.Anything).Once().Run(func(args mock.Arguments) {
			cl = args.Get(1).(config.ChangeListener)
		})
		src.On("GetConfig").Once().Return(newConfig())

		ctx := t.Context()
		r := controller.NewDatabrokerRestartRunner(ctx, src)
		defer r.Close()

		count := 0
		var clients [2]databroker.DataBrokerServiceClient
		err := r.Run(ctx, func(ctx context.Context, client databroker.DataBrokerServiceClient) error {
			clients[count] = client
			count++
			if count == 1 {
				cl(t.Context(), newConfig())
				<-ctx.Done()
				require.ErrorIs(t, context.Cause(ctx), controller.ErrBootstrapConfigurationChanged)
				return context.Cause(ctx)
			}
			return nil
		})
		require.NoError(t, err)
		require.Equal(t, 2, count)
		require.NotSame(t, clients[0], clients[1])
	})
}
