package controlplane

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/config/envoyconfig/filemgr"
	"github.com/pomerium/pomerium/internal/events"
	"github.com/pomerium/pomerium/pkg/cryptutil"
	"github.com/pomerium/pomerium/pkg/netutil"
)

func TestServerHTTP(t *testing.T) {
	t.Parallel()

	ports, err := netutil.AllocatePorts(5)
	require.NoError(t, err)

	ctx := t.Context()
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	cfg := newTestConfig(ports)

	src := config.NewStaticSource(cfg)
	srv, err := NewServer(ctx, cfg, config.NewMetricsManager(ctx, src), events.New(), filemgr.NewManager(filemgr.WithCacheDir(t.TempDir())))
	require.NoError(t, err)
	go srv.Run(ctx)

	t.Run("well-known", func(t *testing.T) {
		res, err := http.Get(fmt.Sprintf("http://localhost:%s/.well-known/pomerium", src.GetConfig().HTTPPort))
		require.NoError(t, err)
		defer res.Body.Close()

		var actual map[string]any
		err = json.NewDecoder(res.Body).Decode(&actual)
		require.NoError(t, err)

		expect := map[string]any{
			"issuer":                           fmt.Sprintf("https://localhost:%s/", src.GetConfig().HTTPPort),
			"authentication_callback_endpoint": "https://authenticate.localhost.pomerium.io/oauth2/callback",
			"frontchannel_logout_uri":          fmt.Sprintf("https://localhost:%s/.pomerium/sign_out", src.GetConfig().HTTPPort),
			"jwks_uri":                         fmt.Sprintf("https://localhost:%s/.well-known/pomerium/jwks.json", src.GetConfig().HTTPPort),
		}
		assert.Equal(t, expect, actual)
	})
	t.Run("jwks", func(t *testing.T) {
		signingKey, err := cfg.Options.GetSigningKey()
		require.NoError(t, err)
		expectedJWK, err := cryptutil.PublicJWKFromBytes(signingKey)
		require.NoError(t, err)
		expectedJWKJSON, err := expectedJWK.MarshalJSON()
		require.NoError(t, err)
		var expectedKey map[string]any
		require.NoError(t, json.Unmarshal(expectedJWKJSON, &expectedKey))

		res, err := http.Get(fmt.Sprintf("http://localhost:%s/.well-known/pomerium/jwks.json", src.GetConfig().HTTPPort))
		require.NoError(t, err)
		defer res.Body.Close()

		var actual map[string]any
		err = json.NewDecoder(res.Body).Decode(&actual)
		require.NoError(t, err)

		assert.Equal(t, map[string]any{"keys": []any{expectedKey}}, actual)
	})
	t.Run("hpke-public-key", func(t *testing.T) {
		hpkePrivateKey, err := cfg.Options.GetHPKEPrivateKey()
		require.NoError(t, err)
		expected := hpkePrivateKey.PublicKey().Bytes()

		res, err := http.Get(fmt.Sprintf("http://localhost:%s/.well-known/pomerium/hpke-public-key", src.GetConfig().HTTPPort))
		require.NoError(t, err)
		defer res.Body.Close()

		bs, err := io.ReadAll(res.Body)
		require.NoError(t, err)
		assert.Equal(t, expected, bs)
	})
}
