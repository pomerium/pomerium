package config_test

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"

	"github.com/pomerium/pomerium/config"
)

func TestLayeredConfig(t *testing.T) {
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

		var dst *config.Config
		layered.OnConfigChange(ctx, func(ctx context.Context, c *config.Config) {
			dst = c
		})

		underlying.SetConfig(ctx, &config.Config{Options: &config.Options{DeriveInternalDomainCert: proto.String("b.com")}})
		assert.Equal(t, "b.com", dst.Options.GetDeriveInternalDomain())
	})
}
