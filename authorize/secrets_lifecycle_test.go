package authorize

import (
	"context"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/open-policy-agent/opa/rego"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"

	"github.com/pomerium/pomerium/authorize/evaluator"
	"github.com/pomerium/pomerium/config"
	hpke_handlers "github.com/pomerium/pomerium/pkg/hpke/handlers"
	"github.com/pomerium/pomerium/pkg/secrets"
	"github.com/pomerium/pomerium/pkg/secrets/resolver"
	"github.com/pomerium/pomerium/pkg/storage"
)

func baseAuthorizeOptions(t *testing.T) *config.Options {
	t.Helper()
	opt := config.NewDefaultOptions()
	opt.DataBroker.ServiceURL = "https://databroker.example.com"
	opt.SharedKey = "E8wWIMnihUx+AUfRegAQDNs8eRb3UrB5G3zlJW9XJDM="

	hpkePrivateKey, err := opt.GetHPKEPrivateKey()
	require.NoError(t, err)
	authnSrv := httptest.NewServer(hpke_handlers.HPKEPublicKeyHandler(hpkePrivateKey.PublicKey()))
	t.Cleanup(authnSrv.Close)
	opt.AuthenticateURLString = authnSrv.URL
	return opt
}

func eventuallyResolves(t *testing.T, a *Authorize, id, want string) {
	t.Helper()
	assert.Eventually(t, func() bool {
		r := a.secretsResolver.Lookup(id)
		return r.Found && r.State == resolver.StateFresh && r.Value == want
	}, 5*time.Second, 50*time.Millisecond)
}

func secretsFetchCount(t *testing.T, reader *sdkmetric.ManualReader) int64 {
	t.Helper()
	var rm metricdata.ResourceMetrics
	require.NoError(t, reader.Collect(context.Background(), &rm))
	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			if m.Name != "secrets.fetches" {
				continue
			}
			if d, ok := m.Data.(metricdata.Sum[int64]); ok {
				var sum int64
				for _, dp := range d.DataPoints {
					sum += dp.Value
				}
				return sum
			}
		}
	}
	return 0
}

func TestNewWithSecrets(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "tok")
	require.NoError(t, os.WriteFile(path, []byte("v1"), 0o600))

	opt := baseAuthorizeOptions(t)
	opt.Secrets = config.SecretsOptions{
		Defaults: config.SecretsDefaultsOptions{Refresh: time.Second, StaleGrace: 2 * time.Second, NegativeTTL: time.Second},
		Bindings: map[string]config.SecretsBindingOptions{"tok": {URL: "file://" + path}},
	}

	// New returns; Run is deliberately NOT called (boot-order regression).
	a, err := New(t.Context(), config.New(opt))
	require.NoError(t, err)

	assert.NotNil(t, a.store.GetSecretsLookup(), "lookup wired into the store")

	// Fetch loops started on Apply inside New, without Run.
	eventuallyResolves(t, a, "tok", "v1")

	// The header injects through a headers evaluator built over the same store
	// New wired the lookup into — no Run required.
	ctx := storage.WithQuerier(t.Context(), storage.NewStaticQuerier())
	he := evaluator.NewHeadersEvaluator(a.store)
	assert.Eventually(t, func() bool {
		res, err := he.Evaluate(ctx, &evaluator.Request{
			Policy: &config.Policy{
				From:              "https://app.example.com",
				SetRequestHeaders: map[string]string{"Authorization": "Bearer ${secret.tok}"},
			},
		}, rego.EvalTime(time.Unix(1686870680, 0)))
		return err == nil && res.Headers.Get("Authorization") == "Bearer v1"
	}, 5*time.Second, 50*time.Millisecond)
}

func TestOnConfigChangeRebindsSecrets(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	p1 := filepath.Join(dir, "tok1")
	p2 := filepath.Join(dir, "tok2")
	require.NoError(t, os.WriteFile(p1, []byte("v1"), 0o600))
	require.NoError(t, os.WriteFile(p2, []byte("v2"), 0o600))

	opt := baseAuthorizeOptions(t)
	opt.Secrets = config.SecretsOptions{
		Defaults: config.SecretsDefaultsOptions{Refresh: time.Second, StaleGrace: 2 * time.Second, NegativeTTL: time.Second},
		Bindings: map[string]config.SecretsBindingOptions{"tok": {URL: "file://" + p1}},
	}

	a, err := New(t.Context(), config.New(opt))
	require.NoError(t, err)
	eventuallyResolves(t, a, "tok", "v1")

	opt.Secrets.Bindings["tok"] = config.SecretsBindingOptions{URL: "file://" + p2}
	a.OnConfigChange(t.Context(), config.New(opt))
	eventuallyResolves(t, a, "tok", "v2")
}

func TestOnConfigChangeKeepsCacheWarm(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "tok")
	require.NoError(t, os.WriteFile(path, []byte("v1"), 0o600))

	reader := sdkmetric.NewManualReader()
	mp := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	res := resolver.New(secrets.DefaultRegistry(), resolver.WithMeter(mp.Meter("test")))

	opt := baseAuthorizeOptions(t)
	// Long refresh so no scheduled re-fetch pollutes the assertion.
	opt.Secrets = config.SecretsOptions{
		Bindings: map[string]config.SecretsBindingOptions{"tok": {URL: "file://" + path}},
	}

	a, err := New(t.Context(), config.New(opt), withSecretsResolver(res))
	require.NoError(t, err)
	eventuallyResolves(t, a, "tok", "v1")

	before := secretsFetchCount(t, reader)
	require.GreaterOrEqual(t, before, int64(1))

	// A config change that does not touch the binding.
	opt.LogLevel = "debug"
	a.OnConfigChange(t.Context(), config.New(opt))
	time.Sleep(500 * time.Millisecond)

	assert.Equal(t, before, secretsFetchCount(t, reader), "warm binding must not be re-fetched on config change")
}

func TestNewDoesNotBlockOnUnresolvable(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "tok") // does not exist yet

	opt := baseAuthorizeOptions(t)
	opt.Secrets = config.SecretsOptions{
		Defaults: config.SecretsDefaultsOptions{Refresh: time.Second, StaleGrace: 2 * time.Second, NegativeTTL: time.Second},
		Bindings: map[string]config.SecretsBindingOptions{"tok": {URL: "file://" + path}},
	}

	// New returns promptly even though the secret is unresolvable.
	done := make(chan *Authorize, 1)
	go func() {
		a, err := New(t.Context(), config.New(opt))
		require.NoError(t, err)
		done <- a
	}()
	var a *Authorize
	select {
	case a = <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("New blocked on an unresolvable secret")
	}

	// The unresolved binding reads as not-fresh (a referencing request 503s).
	r := a.secretsResolver.Lookup("tok")
	assert.True(t, r.State != resolver.StateFresh && r.State != resolver.StateStale, "unresolved => not servable")

	// Once the file appears, it resolves without any config reload.
	require.NoError(t, os.WriteFile(path, []byte("late"), 0o600))
	eventuallyResolves(t, a, "tok", "late")
}
