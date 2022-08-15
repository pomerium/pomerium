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

func TestServerWellKnown(t *testing.T) {
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
	src := config.NewStaticSource(cfg)
	srv, err := NewServer(cfg, config.NewMetricsManager(ctx, src), events.New())
	require.NoError(t, err)
	go srv.Run(ctx)

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
}
