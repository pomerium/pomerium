package authorize_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/testenv"
	"github.com/pomerium/pomerium/internal/testenv/scenarios"
	"github.com/pomerium/pomerium/internal/testenv/snippets"
	"github.com/pomerium/pomerium/internal/testenv/upstreams"
	"github.com/pomerium/pomerium/internal/testenv/values"
)

// TestSecretInjectionEndToEnd is the feature's proof: a file:// secret is
// injected into a per-route set_request_headers value, rotated live without a
// config reload, and — once removed past its stale grace — causes the request
// to fail closed with a 503.
func TestSecretInjectionEndToEnd(t *testing.T) {
	dir := t.TempDir()
	secretPath := filepath.Join(dir, "tok")
	require.NoError(t, os.WriteFile(secretPath, []byte("v1"), 0o600))

	env := testenv.New(t)
	env.Add(scenarios.NewIDP([]*scenarios.User{{Email: "user@example.com"}}))

	env.Add(testenv.ModifierFunc(func(_ context.Context, cfg *config.Config) {
		cfg.Options.Secrets = config.SecretsOptions{
			Defaults: config.SecretsDefaultsOptions{
				Refresh:     time.Second,
				StaleGrace:  2 * time.Second,
				NegativeTTL: time.Second,
			},
			Bindings: map[string]config.SecretsBindingOptions{
				"tok": {URL: "file://" + secretPath},
			},
		}
	}))

	up := upstreams.HTTP(nil)
	up.Handle("/echo", func(w http.ResponseWriter, r *http.Request) {
		hdrs := make(map[string]string, len(r.Header))
		for k := range r.Header {
			hdrs[strings.ToLower(k)] = r.Header.Get(k)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(hdrs)
	})
	route := up.Route().
		From(env.SubdomainURL("secrets")).
		To(values.Bind(up.Addr(), func(addr string) string {
			return fmt.Sprintf("http://%s", addr)
		})).
		Policy(func(p *config.Policy) {
			p.AllowAnyAuthenticatedUser = true
			p.SetRequestHeaders = map[string]string{"X-Secret": "injected=${secret.tok}"}
		})
	env.AddUpstream(up)

	env.Start()
	snippets.WaitStartupComplete(env)

	// probe returns the upstream-observed X-Secret header and whether the
	// request succeeded (HTTP 200). The request context is bounded so that a
	// persistent fail-closed 503 (which the test client retries on) does not
	// block the probe.
	probe := func() (value string, ok bool) {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		resp, err := up.Get(route,
			upstreams.AuthenticateAs("user@example.com"),
			upstreams.Path("/echo"),
			upstreams.Context(ctx))
		if err != nil || resp.StatusCode != http.StatusOK {
			return "", false
		}
		defer resp.Body.Close()
		var hdrs map[string]string
		if err := json.NewDecoder(resp.Body).Decode(&hdrs); err != nil {
			return "", false
		}
		return hdrs["x-secret"], true
	}

	// The initial value is injected (the first fetch is asynchronous on boot).
	assert.Eventually(t, func() bool {
		v, ok := probe()
		return ok && v == "injected=v1"
	}, 20*time.Second, time.Second, "initial secret value should be injected")

	// Rotation: rewrite the file; the new value becomes visible with no reload.
	require.NoError(t, os.WriteFile(secretPath, []byte("v2"), 0o600))
	assert.Eventually(t, func() bool {
		v, ok := probe()
		return ok && v == "injected=v2"
	}, 20*time.Second, time.Second, "rotated value should become visible")

	// Removal: once the stale grace elapses, the request fails closed (no 200).
	require.NoError(t, os.Remove(secretPath))
	assert.Eventually(t, func() bool {
		_, ok := probe()
		return !ok
	}, 30*time.Second, time.Second, "removed secret should fail closed")
}
