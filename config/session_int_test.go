package config_test

import (
	"context"
	"io"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/testenv"
	"github.com/pomerium/pomerium/internal/testenv/scenarios"
	"github.com/pomerium/pomerium/internal/testenv/snippets"
	"github.com/pomerium/pomerium/internal/testenv/upstreams"
	configpb "github.com/pomerium/pomerium/pkg/grpc/config"
	"github.com/pomerium/pomerium/pkg/nullable"
)

func TestBearerTokenFormat(t *testing.T) {
	run := func(t *testing.T, useProxyProtocol bool) {
		t.Helper()

		env := testenv.New(t)

		env.Add(testenv.ModifierFunc(func(_ context.Context, cfg *config.Config) {
			cfg.Options.BearerTokenFormat = nullable.From(configpb.BearerTokenFormat_BEARER_TOKEN_FORMAT_IDP_ACCESS_TOKEN)
			cfg.Options.UseProxyProtocol = useProxyProtocol
		}))

		env.Add(scenarios.NewIDP([]*scenarios.User{{Email: "test@example.com"}}))

		up := upstreams.HTTP(nil)
		up.Handle("/", func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte(r.Header.Get("Access-Token")))
		})
		route := up.Route().
			From(env.SubdomainURL("http")).
			Policy(func(p *config.Policy) {
				p.AllowAnyAuthenticatedUser = true
				p.SetRequestHeaders = map[string]string{"access-token": "$pomerium.access_token"}
			})
		env.AddUpstream(up)

		env.Start()
		snippets.WaitStartupComplete(env)

		// first request is a normal login
		r1, err := up.Get(route,
			upstreams.AuthenticateAs("test@example.com"))
		require.NoError(t, err)
		defer r1.Body.Close()
		accessToken, err := io.ReadAll(r1.Body)
		require.NoError(t, err)

		// second request is via the authorization header
		r2, err := up.Get(route,
			upstreams.Headers(map[string]string{
				"Authorization": "Bearer " + string(accessToken),
			}))
		require.NoError(t, err)
		defer r2.Body.Close()
		data, err := io.ReadAll(r2.Body)
		require.NoError(t, err)
		assert.Equal(t, string(accessToken), string(data))
	}
	t.Run("without proxy protocol", func(t *testing.T) { run(t, false) })
	t.Run("with proxy protocol", func(t *testing.T) { run(t, true) })
}
