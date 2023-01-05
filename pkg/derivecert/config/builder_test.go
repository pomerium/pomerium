package config_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/pkg/cryptutil"
	dcfg "github.com/pomerium/pomerium/pkg/derivecert/config"
)

func TestBuild(t *testing.T) {
	build := dcfg.NewBuilder()

	key := cryptutil.NewBase64Key()

	cfgA := config.Config{Options: &config.Options{SharedKey: key}}
	t.Run("no domain requested", func(t *testing.T) {
		require.NoError(t, build(&cfgA))
		assert.Empty(t, cfgA.DerivedCAPEM)
		assert.Empty(t, cfgA.DerivedCertificates)
	})

	cfgA.Options.DeriveInternalDomainCert = proto.String("example.com")
	t.Run("generate server cert", func(t *testing.T) {
		require.NoError(t, build(&cfgA))
		assert.NotEmpty(t, cfgA.DerivedCAPEM)
		assert.Len(t, cfgA.DerivedCertificates, 1)
	})

	cfgB := config.Config{Options: &config.Options{
		SharedKey:                key,
		DeriveInternalDomainCert: proto.String("example.com"),
	}}
	t.Run("caching", func(t *testing.T) {
		require.NoError(t, build(&cfgB))
		assert.Equal(t, cfgA.DerivedCAPEM, cfgB.DerivedCAPEM)
		assert.Equal(t, cfgA.DerivedCertificates[0].Certificate, cfgB.DerivedCertificates[0].Certificate)
	})

	t.Run("no domain requested after run", func(t *testing.T) {
		cfg := config.Config{Options: &config.Options{SharedKey: key}}
		require.NoError(t, build(&cfg))
		assert.Empty(t, cfg.DerivedCAPEM)
		assert.Empty(t, cfg.DerivedCertificates)
	})

	cfgB.Options.DeriveInternalDomainCert = proto.String("example2.com")
	t.Run("ca caching", func(t *testing.T) {
		require.NoError(t, build(&cfgB))
		assert.Equal(t, cfgA.DerivedCAPEM, cfgB.DerivedCAPEM)
		assert.NotEqual(t, cfgA.DerivedCertificates[0].Certificate, cfgB.DerivedCertificates[0].Certificate)
	})
}
