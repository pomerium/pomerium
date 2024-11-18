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
	"github.com/pomerium/pomerium/pkg/netutil"
)

func TestServerHTTP(t *testing.T) {
	ports, err := netutil.AllocatePorts(5)
	require.NoError(t, err)

	ctx := context.Background()
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	cfg := &config.Config{
		GRPCPort:     ports[0],
		HTTPPort:     ports[1],
		OutboundPort: ports[2],
		MetricsPort:  ports[3],
		DebugPort:    ports[4],

		Options: config.NewDefaultOptions(),
	}
	cfg.Options.AuthenticateURLString = "https://authenticate.localhost.pomerium.io"
	cfg.Options.SigningKey = "LS0tLS1CRUdJTiBFQyBQUklWQVRFIEtFWS0tLS0tCk1IY0NBUUVFSUpCMFZkbko1VjEvbVlpYUlIWHhnd2Q0Yzd5YWRTeXMxb3Y0bzA1b0F3ekdvQW9HQ0NxR1NNNDkKQXdFSG9VUURRZ0FFVUc1eENQMEpUVDFINklvbDhqS3VUSVBWTE0wNENnVzlQbEV5cE5SbVdsb29LRVhSOUhUMwpPYnp6aktZaWN6YjArMUt3VjJmTVRFMTh1dy82MXJVQ0JBPT0KLS0tLS1FTkQgRUMgUFJJVkFURSBLRVktLS0tLQo="
	cfg.Options.SharedKey = "JDNjY2ITDlARvNaQXjc2Djk+GA6xeCy4KiozmZfdbTs="

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
		res, err := http.Get(fmt.Sprintf("http://localhost:%s/.well-known/pomerium/jwks.json", src.GetConfig().HTTPPort))
		require.NoError(t, err)
		defer res.Body.Close()

		var actual map[string]any
		err = json.NewDecoder(res.Body).Decode(&actual)
		require.NoError(t, err)

		expect := map[string]any{
			"keys": []any{
				map[string]any{
					"alg": "ES256",
					"crv": "P-256",
					"kid": "5b419ade1895fec2d2def6cd33b1b9a018df60db231dc5ecb85cbed6d942813c",
					"kty": "EC",
					"use": "sig",
					"x":   "UG5xCP0JTT1H6Iol8jKuTIPVLM04CgW9PlEypNRmWlo",
					"y":   "KChF0fR09zm884ymInM29PtSsFdnzExNfLsP-ta1AgQ",
				},
			},
		}
		assert.Equal(t, expect, actual)
	})
	t.Run("hpke-public-key", func(t *testing.T) {
		res, err := http.Get(fmt.Sprintf("http://localhost:%s/.well-known/pomerium/hpke-public-key", src.GetConfig().HTTPPort))
		require.NoError(t, err)
		defer res.Body.Close()

		bs, err := io.ReadAll(res.Body)
		require.NoError(t, err)
		assert.Equal(t, []byte{
			0x4f, 0x47, 0x1b, 0x36, 0xb2, 0x5b, 0x3b, 0xd8,
			0xa7, 0xf8, 0x58, 0x28, 0xc0, 0xa0, 0x0f, 0xf8,
			0x75, 0xfa, 0x0a, 0x2f, 0x2a, 0xe7, 0x48, 0x28,
			0xa4, 0xeb, 0x79, 0xda, 0xc7, 0x61, 0x78, 0x78,
		}, bs)
	})
}
