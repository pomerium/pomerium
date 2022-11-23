package controlplane

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pomerium/pomerium/config"
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
	srv, err := NewServer(cfg, config.NewMetricsManager(ctx, src), events.New())
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
			"authentication_callback_endpoint": "https://authenticate.localhost.pomerium.io/oauth2/callback",
			"frontchannel_logout_uri":          "https://authenticate.localhost.pomerium.io/.pomerium/sign_out",
			"jwks_uri":                         "https://authenticate.localhost.pomerium.io/.well-known/pomerium/jwks.json",
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
				map[string]any{
					"kty": "OKP",
					"kid": "pomerium/hpke",
					"crv": "X25519",
					"x":   "T0cbNrJbO9in-FgowKAP-HX6Ci8q50gopOt52sdheHg",
				},
			},
		}
		assert.Equal(t, expect, actual)
	})
}
