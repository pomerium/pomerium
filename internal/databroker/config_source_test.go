package databroker

import (
	"context"
	"encoding/base64"
	"net"
	"net/url"
	"slices"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/trace/noop"
	"google.golang.org/grpc"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/signal"
	"github.com/pomerium/pomerium/pkg/cryptutil"
	configpb "github.com/pomerium/pomerium/pkg/grpc/config"
	databrokerpb "github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/protoutil"
)

func TestConfigSource(t *testing.T) {
	t.Parallel()

	ctx := t.Context()
	ctx, clearTimeout := context.WithTimeout(ctx, 50*time.Second)
	defer clearTimeout()

	generateCert := func(name string) ([]byte, []byte) {
		cert, err := cryptutil.GenerateCertificate(nil, name)
		require.NoError(t, err)
		certPEM, keyPEM, err := cryptutil.EncodeCertificate(cert)
		require.NoError(t, err)
		return certPEM, keyPEM
	}

	li, err := net.Listen("tcp", "127.0.0.1:0")
	if !assert.NoError(t, err) {
		return
	}
	defer func() { _ = li.Close() }()
	_, outboundPort, _ := net.SplitHostPort(li.Addr().String())

	srv := NewBackendServer(noop.NewTracerProvider())
	t.Cleanup(srv.Stop)

	s := grpc.NewServer()
	databrokerpb.RegisterDataBrokerServiceServer(s, srv)
	go func() { _ = s.Serve(li) }()

	u, _ := url.Parse("https://to.example.com")
	base := config.NewDefaultOptions()
	base.DataBroker.ServiceURL = "http://" + li.Addr().String()
	base.InsecureServer = true
	base.GRPCInsecure = new(true)
	base.Policies = append(base.Policies, config.Policy{
		From: "https://pomerium.io", To: config.WeightedURLs{
			{URL: *u},
		}, AllowedUsers: []string{"foo@bar.com"},
	})
	certPEM, keyPEM := generateCert("*.example.com")
	base.Cert, base.Key = base64.StdEncoding.EncodeToString(certPEM), base64.StdEncoding.EncodeToString(keyPEM)

	cfg := config.New(base)
	cfg.OutboundPort = outboundPort
	baseSource := config.NewStaticSource(cfg)
	done := signal.New()
	ch := done.Bind()
	NewConfigSource(ctx, noop.NewTracerProvider(), baseSource, EnableConfigValidation(true),
		func(ctx context.Context, cfg *config.Config) {
			if len(cfg.Options.AdditionalPolicies) == 1 {
				done.Broadcast(ctx)
				assert.Len(t, cfg.Options.CertificateFiles, 0, "ignores overlapping certificate")
			}
		})

	route := &configpb.Route{
		From: "https://from.example.com",
		To:   []string{"https://to.example.com"},
	}
	cert := &configpb.Settings_Certificate{}
	cert.CertBytes, cert.KeyBytes = generateCert("*.example.com")
	data := protoutil.NewAny(&configpb.Config{
		Name:   "config",
		Routes: []*configpb.Route{route},
		Settings: &configpb.Settings{
			Certificates: []*configpb.Settings_Certificate{cert},
		},
	})
	_, _ = srv.Put(ctx, &databrokerpb.PutRequest{
		Records: []*databrokerpb.Record{{
			Type: data.TypeUrl,
			Id:   "1",
			Data: data,
		}},
	})

	select {
	case <-ctx.Done():
		t.Error(context.Cause(ctx))
	case <-ch:
	}

	srv.Stop()
}

func TestAllDBConfigs(t *testing.T) {
	baseSource := config.NewStaticSource(config.New(nil))
	src := NewConfigSource(t.Context(), noop.NewTracerProvider(), baseSource, EnableConfigValidation(false))

	insert := func(m map[string]dbConfig, cfgs ...dbConfig) {
		for _, cfg := range cfgs {
			m[cfg.Name] = cfg
		}
	}

	config1 := dbConfig{&configpb.Config{Name: "config1"}, 101}
	config2 := dbConfig{&configpb.Config{Name: "config2"}, 102}
	config3 := dbConfig{&configpb.Config{Name: "config3"}, 103}
	insert(src.dbConfigs, config1, config2, config3)

	versionedConfig1 := dbConfig{&configpb.Config{Name: "versionedConfig1"}, 104}
	versionedConfig2 := dbConfig{&configpb.Config{Name: "versionedConfig2"}, 105}
	versionedConfig3 := dbConfig{&configpb.Config{Name: "versionedConfig3"}, 106}
	insert(src.dbVersionedConfigs, versionedConfig1, versionedConfig2, versionedConfig3)

	src.standardConfigReady = true
	src.versionedConfigReady = true

	// allDBConfigsLocked() should return the union of dbConfigs and dbVersionedConfigs.
	assert.ElementsMatch(t, []*configpb.Config{
		config1.Config,
		config2.Config,
		config3.Config,
		versionedConfig1.Config,
		versionedConfig2.Config,
		versionedConfig3.Config,
	}, slices.Collect(src.allDBConfigsLocked()))

	// allSortedDBConfigsLocked() should return the sorted union of dbConfigs and dbVersionedConfigs.
	assert.Equal(t, []*configpb.Config{
		config1.Config,
		config2.Config,
		config3.Config,
		versionedConfig1.Config,
		versionedConfig2.Config,
		versionedConfig3.Config,
	}, slices.Collect(src.allSortedDBConfigsLocked()))
}

func TestConfigSourceSettingsRuntimeFlagsOverlay(t *testing.T) {
	t.Parallel()

	authenticationMode := configpb.PostgresAuthenticationMode_POSTGRES_AUTHENTICATION_MODE_MANAGED
	upstreamTLSMode := configpb.PostgresUpstreamTLSMode_POSTGRES_UPSTREAM_TLS_MODE_VERIFY_FULL
	postgresRoute := &configpb.Route{
		From: "postgres://db.example.com",
		To:   []string{"postgres://postgres.internal:5432"},
		Postgres: &configpb.PostgresRouteSettings{
			AuthenticationMode: &authenticationMode,
			Username:           "application-role",
			Database:           "application-db",
			Password:           "secret",
			UpstreamTlsMode:    &upstreamTLSMode,
		},
	}

	options := config.NewDefaultOptions()
	options.RuntimeFlags[config.RuntimeFlagPostgres] = true
	underlying := config.New(options)
	address := "127.0.0.1:15432"
	src := &ConfigSource{
		underlyingConfig: underlying,
		dbConfigs: map[string]dbConfig{
			"dashboard-settings": {
				Config: &configpb.Config{
					Settings: &configpb.Settings{PostgresAddress: &address},
				},
			},
			"dashboard-route-postgres": {
				Config: &configpb.Config{Routes: []*configpb.Route{postgresRoute}},
			},
		},
		dbVersionedConfigs:  map[string]dbConfig{},
		standardConfigReady: true,
		enableValidation:    true,
	}

	rebuild := func(t *testing.T) *config.Config {
		t.Helper()
		computed := underlying.Clone()
		require.NoError(t, src.buildNewConfigLocked(t.Context(), computed))
		assert.Equal(t, address, computed.Options.PostgresAddr)
		assert.NotNil(t, computed.Options.GetRouteForPostgresHostname("db.example.com"))
		return computed
	}
	assertUnderlyingUnchanged := func(t *testing.T) {
		t.Helper()
		assert.True(t, underlying.Options.IsRuntimeFlagSet(config.RuntimeFlagPostgres))
		assert.False(t, underlying.Options.IsRuntimeFlagSet(config.RuntimeFlagMCP))
		assert.Empty(t, underlying.Options.PostgresAddr)
		assert.Empty(t, underlying.Options.AdditionalPolicies)
	}

	t.Run("absent", func(t *testing.T) {
		computed := rebuild(t)
		assert.True(t, computed.Options.IsRuntimeFlagSet(config.RuntimeFlagPostgres))
		assertUnderlyingUnchanged(t)
	})

	t.Run("explicit override is removed", func(t *testing.T) {
		src.dbConfigs["runtime-flags"] = dbConfig{Config: &configpb.Config{
			Settings: &configpb.Settings{RuntimeFlags: map[string]bool{
				string(config.RuntimeFlagPostgres): false,
			}},
		}}
		computed := rebuild(t)
		assert.False(t, computed.Options.IsRuntimeFlagSet(config.RuntimeFlagPostgres))
		assertUnderlyingUnchanged(t)

		delete(src.dbConfigs, "runtime-flags")
		computed = rebuild(t)
		assert.True(t, computed.Options.IsRuntimeFlagSet(config.RuntimeFlagPostgres))
		assertUnderlyingUnchanged(t)
	})

	t.Run("unrelated override is removed", func(t *testing.T) {
		src.dbConfigs["runtime-flags"] = dbConfig{Config: &configpb.Config{
			Settings: &configpb.Settings{RuntimeFlags: map[string]bool{
				string(config.RuntimeFlagMCP): true,
			}},
		}}
		computed := rebuild(t)
		assert.True(t, computed.Options.IsRuntimeFlagSet(config.RuntimeFlagPostgres))
		assert.True(t, computed.Options.IsRuntimeFlagSet(config.RuntimeFlagMCP))
		assertUnderlyingUnchanged(t)

		delete(src.dbConfigs, "runtime-flags")
		computed = rebuild(t)
		assert.True(t, computed.Options.IsRuntimeFlagSet(config.RuntimeFlagPostgres))
		assert.False(t, computed.Options.IsRuntimeFlagSet(config.RuntimeFlagMCP))
		assertUnderlyingUnchanged(t)
	})
}
