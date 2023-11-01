package config_test

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"

	"github.com/pomerium/pomerium/config"
)

func TestLayeredConfig(t *testing.T) {
	t.Parallel()

	ctx := context.Background()

	t.Run("error on initial build", func(t *testing.T) {
		underlying := config.NewStaticSource(&config.Config{})
		_, err := config.NewLayeredSource(ctx, underlying, func(c *config.Config) error {
			return errors.New("error")
		})
		require.Error(t, err)
	})

	t.Run("propagate new config on error", func(t *testing.T) {
		underlying := config.NewStaticSource(&config.Config{Options: &config.Options{DeriveInternalDomainCert: proto.String("a.com")}})
		layered, err := config.NewLayeredSource(ctx, underlying, func(c *config.Config) error {
			if c.Options.GetDeriveInternalDomain() == "b.com" {
				return errors.New("reject update")
			}
			return nil
		})
		require.NoError(t, err)

		var dst atomic.Pointer[config.Config]
		layered.OnConfigChange(ctx, func(ctx context.Context, c *config.Config) {
			dst.Store(c)
		})

		underlying.SetConfig(ctx, &config.Config{Options: &config.Options{DeriveInternalDomainCert: proto.String("b.com")}})
		assert.Eventually(t, func() bool {
			cfg := dst.Load()
			if cfg == nil {
				return false
			}
			return cfg.Options.GetDeriveInternalDomain() == "b.com"
		}, time.Millisecond*100, time.Millisecond)
	})
}
