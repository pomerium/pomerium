package analytics

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/posthog/posthog-go"
	"github.com/shirou/gopsutil/v4/cpu"
	"github.com/shirou/gopsutil/v4/host"
	"github.com/shirou/gopsutil/v4/mem"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/volatiletech/null/v9"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/pkg/cryptutil"
	configpb "github.com/pomerium/pomerium/pkg/grpc/config"
	"github.com/pomerium/pomerium/pkg/logfields"
	"github.com/pomerium/pomerium/pkg/nullable"
	"github.com/pomerium/pomerium/pkg/policy/parser"
)

func TestCreatePosthogPropertiesForCertificates(t *testing.T) {
	t.Parallel()
	cert, err := cryptutil.GenerateCertificate(nil, "example.com")
	require.NoError(t, err)
	certBS, keyBS, err := cryptutil.EncodeCertificate(cert)
	require.NoError(t, err)
	p := New().(*reporter).CreatePosthogPropertiesForCertificates(
		&config.Config{Options: &config.Options{
			CertificateData: []*configpb.Settings_Certificate{{
				CertBytes: certBS,
				KeyBytes:  keyBS,
			}},
		}},
	)
	assert.Equal(t, posthog.Properties{
		"certificate_count": 1,
	}, p)
}

func TestCreatePosthogPropertiesForCPU(t *testing.T) {
	t.Parallel()
	p := New().(*reporter).CreatePosthogPropertiesForCPU([]cpu.InfoStat{
		{VendorID: "GenuineIntel", Family: "6", Model: "197", ModelName: "Intel(R) Core(TM) Ultra 9 285H", Cores: 1},
		{VendorID: "GenuineIntel", Family: "6", Model: "197", ModelName: "Intel(R) Core(TM) Ultra 9 285H", Cores: 1},
	})
	assert.Equal(t, posthog.Properties{
		"cpu_count": 2,
	}, p)
}

func TestCreatePosthogPropertiesForHost(t *testing.T) {
	t.Parallel()
	p := New().(*reporter).CreatePosthogPropertiesForHost(
		&host.InfoStat{
			HostID:               "example",
			Hostname:             "example",
			OS:                   "linux",
			Platform:             "ubuntu",
			PlatformFamily:       "debian",
			PlatformVersion:      "26.04",
			KernelVersion:        "7.0.0-38-generic",
			KernelArch:           "x86_64",
			VirtualizationSystem: "kvm",
		},
	)
	assert.Equal(t, posthog.Properties{
		"kernel_arch":           "x86_64",
		"os":                    "linux",
		"platform":              "ubuntu",
		"platform_version":      "26.04",
		"virtualization_system": "kvm",
	}, p)
}

func TestCreatePosthogPropertiesForMemory(t *testing.T) {
	t.Parallel()
	p := New().(*reporter).CreatePosthogPropertiesForMemory(
		&mem.VirtualMemoryStat{
			Total:     34_359_738_368,
			Available: 7_321_200_400,
			Used:      34_359_738_368 - 7_321_200_400,
		},
	)
	assert.Equal(t, posthog.Properties{
		"mem_total_gib": 32.,
	}, p)

	// rounded to the nearest GiB
	p = New().(*reporter).CreatePosthogPropertiesForMemory(&mem.VirtualMemoryStat{Total: 16_642_998_272}) // ~15.5 GiB
	assert.Equal(t, posthog.Properties{"mem_total_gib": 16.}, p)
	p = New().(*reporter).CreatePosthogPropertiesForMemory(&mem.VirtualMemoryStat{Total: 16_106_127_360}) // 15 GiB
	assert.Equal(t, posthog.Properties{"mem_total_gib": 15.}, p)
}

func TestCreatePosthogPropertiesForRoutes(t *testing.T) {
	t.Parallel()
	cfg := &config.Config{Options: config.NewDefaultOptions()}
	cfg.Options.SharedKey = base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0xAA}, 32))
	for i := range 100 {
		cfg.Options.Routes = append(cfg.Options.Routes,
			config.Policy{
				AllowPublicUnauthenticatedAccess: true,
				From:                             fmt.Sprintf("https://a.b.c.d.route-%02d.com", i),
			},
			config.Policy{
				AllowedUsers: []string{"u1", "u2", "u3"},
				From:         fmt.Sprintf("https://a.b.c.route-%02d.com", i),
				MCP:          &config.MCP{Server: &config.MCPServer{}},
			},
			config.Policy{
				From: fmt.Sprintf("ssh://a.b.c.route-%02d.com", i),
			},
			config.Policy{
				From: fmt.Sprintf("tcp+https://a.b.c.route-%02d.com:9000", i),
			},
			config.Policy{
				From: fmt.Sprintf("udp+https://a.b.c.route-%02d.com:9000", i),
			},
			config.Policy{
				From:                          fmt.Sprintf("https://a.b.route-%02d.com", i),
				KubernetesServiceAccountToken: "TOKEN",
			},
			config.Policy{
				From: fmt.Sprintf("https://a.route-%02d.com", i),
				MCP:  &config.MCP{Server: &config.MCPServer{}, Client: &config.MCPClient{}},
			})
	}
	p := New().(*reporter).CreatePosthogPropertiesForRoutes(cfg)
	assert.Equal(t, posthog.Properties{
		"route_count": 700.,
		"route_types": map[string]any{
			"http":       100.,
			"kubernetes": 100.,
			"mcp_server": 200.,
			"ssh":        100.,
			"tcp":        100.,
			"udp":        100.,
		},
	}, p)
}

func TestCreatePosthogPropertiesForPolicies(t *testing.T) {
	t.Parallel()
	cfg := &config.Config{Options: config.NewDefaultOptions()}
	cfg.Options.SharedKey = base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0xAA}, 32))
	cfg.Options.Routes = []config.Policy{
		{
			AllowPublicUnauthenticatedAccess: true,
			Policy:                           mustParsePPL(t, `{"allow": {"or": [{"authenticated_user": 1}]}}`),
		},
		{
			AllowedUsers: []string{"u1", "u2", "u3"},
			Policy:       mustParsePPL(t, `{"allow": {"and": [{"accept": 1}]}}`),
		},
		{
			SubPolicies: []config.SubPolicy{{
				ID:        "p1",
				SourcePPL: `{"allow": {"nor": [{"domain": "example.com"}]}}`,
			}},
		},
		{
			SubPolicies: []config.SubPolicy{{
				ID:        "p1",
				SourcePPL: `{"allow": {"nor": [{"domain": "example.com"}]}}`,
			}},
		},
	}
	p := New().(*reporter).CreatePosthogPropertiesForPolicies(cfg)
	assert.Equal(t, posthog.Properties{
		"policy_count": 3.,
		"ppl_criteria": map[string]any{
			"accept":             2.,
			"authenticated_user": 1.,
			"domain":             2.,
			"email":              1.,
			"user":               1.,
		},
		"ppl_operators": map[string]any{
			"and": 1.,
			"nor": 1.,
			"or":  3.,
		},
		"shared_policy_count": 1.,
	}, p)
}

func TestCreatePosthogPropertiesForRuntimeFlags(t *testing.T) {
	t.Parallel()

	cfg := &config.Config{Options: config.NewDefaultOptions()}
	p := New().(*reporter).CreatePosthogPropertiesForRuntimeFlags(cfg)
	assert.Equal(t, posthog.Properties{
		"changed_runtime_flags": []any{},
	}, p)

	cfg.Options.RuntimeFlags[config.RuntimeFlagMCP] = false
	cfg.Options.RuntimeFlags[config.RuntimeFlagSSHRoutesPortal] = true
	cfg.Options.RuntimeFlags["some_unknown_flag"] = true
	cfg.Options.RuntimeFlags["another_unknown_flag"] = false
	delete(cfg.Options.RuntimeFlags, config.RuntimeFlagRoutesPortal)        // missing means false
	delete(cfg.Options.RuntimeFlags, config.RuntimeFlagDebugAdminEndpoints) // false by default
	p = New().(*reporter).CreatePosthogPropertiesForRuntimeFlags(cfg)
	assert.Equal(t, posthog.Properties{
		"changed_runtime_flags": []any{
			"mcp",
			"other",
			"routes_portal",
			"ssh_routes_portal",
		},
	}, p)
}

func TestCreatePosthogPropertiesForSettings(t *testing.T) {
	t.Parallel()
	cfg := &config.Config{Options: config.NewDefaultOptions()}
	cfg.Options.SharedKey = base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0xAA}, 32))
	p := New().(*reporter).CreatePosthogPropertiesForSettings(cfg)
	assert.Equal(t, posthog.Properties{
		"databroker_storage_type": "memory",
		"identity_provider":       "none",
		"log_level":               "info",
		"originator_id":           "none",
		"proxy_log_level":         "info",
		"services":                "all",
		"changed_settings":        []any{},
	}, p)

	cfg.Options.AccessLogFields = []logfields.AccessLogField{logfields.AccessLogFieldAuthority}
	cfg.Options.Tracing.OtelBspMaxExportBatchSize = new(int32(11))
	cfg.Options.DNS.UDPMaxQueries = null.NewUint32(87, true)
	cfg.Options.AutocertOptions.MustStaple = true
	cfg.Options.MetricsBasicAuth = "BASIC:AUTH"
	cfg.Options.EnvoyAdminAccessLogPath = "/tmp/some/path"
	cfg.Options.EnvoyBindConfigFreebind = null.BoolFrom(true)
	cfg.Options.DataBroker.ClusterLeaderID = null.StringFrom("LEADER")
	cfg.Options.BrandingOptions = &configpb.Settings{PrimaryColor: new("#FFF000")}
	cfg.Options.CookieName = "_custom_cookie"
	cfg.Options.ReadTimeout = time.Second * 10000
	cfg.Options.DownstreamMTLS.MaxVerifyDepth = new(uint32(3))
	cfg.Options.Scopes = []string{"openid"}
	cfg.Options.DeriveInternalDomainCert = new("example.com")
	cfg.Options.CookieSecret = base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0xBB}, 32))
	cfg.Options.ClientSecret = "SECRET"
	cfg.Options.Provider = "oidc"
	cfg.Options.LogLevel = config.LogLevelDebug
	cfg.Options.RuntimeFlags = map[config.RuntimeFlag]bool{config.RuntimeFlagMCP: false}
	cfg.Options.Routes = []config.Policy{{From: "https://from.example.com", PassIdentityHeaders: new(true)}}
	p = New().(*reporter).CreatePosthogPropertiesForSettings(cfg)
	assert.Equal(t, []any{
		"autocert",
		"branding",
		"cookie",
		"databroker_cluster",
		"dns",
		"downstream_mtls",
		"envoy_admin",
		"envoy_bind",
		"idp_scopes",
		"log_fields",
		"metrics",
		"timeouts",
		"tls_derive",
		"tracing",
	}, p["changed_settings"])
}

func TestCreatePosthogPropertiesForSettingsValues(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name          string
		modify        func(o *config.Options)
		key, expected string
	}{
		{"originator unset", func(_ *config.Options) {}, "originator_id", "none"},
		{"originator empty", func(o *config.Options) { o.OriginatorID = nullable.From("") }, "originator_id", "none"},
		{"originator local", func(o *config.Options) { o.OriginatorID = nullable.From("local") }, "originator_id", "local"},
		{"originator terraform", func(o *config.Options) { o.OriginatorID = nullable.From("terraform") }, "originator_id", "terraform"},
		{"originator other", func(o *config.Options) { o.OriginatorID = nullable.From("my-script") }, "originator_id", "other"},
		{"services all", func(o *config.Options) { o.Services = "all" }, "services", "all"},
		{"services normalized", func(o *config.Options) { o.Services = " Proxy, authorize,proxy," }, "services", "authorize,proxy"},
		{"services sorted", func(o *config.Options) { o.Services = "proxy,authorize" }, "services", "authorize,proxy"},
		{"log level unset", func(o *config.Options) { o.LogLevel = config.LogLevelUnset }, "log_level", "info"},
		{"log level warning", func(o *config.Options) { o.LogLevel = config.LogLevelWarning }, "log_level", "warn"},
		{"log level unknown", func(o *config.Options) { o.LogLevel = "unknown" }, "log_level", "other"},
		{"proxy log level set", func(o *config.Options) { o.ProxyLogLevel = config.LogLevelWarning }, "proxy_log_level", "warn"},
		{"proxy log level from log level", func(o *config.Options) { o.LogLevel = config.LogLevelError }, "proxy_log_level", "error"},
		{"proxy log level default", func(o *config.Options) { o.LogLevel = config.LogLevelUnset }, "proxy_log_level", "debug"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			cfg := &config.Config{Options: config.NewDefaultOptions()}
			tc.modify(cfg.Options)
			p := New().(*reporter).CreatePosthogPropertiesForSettings(cfg)
			assert.Equal(t, tc.expected, p[tc.key])
		})
	}
}

func TestChangedSettingsRules(t *testing.T) {
	t.Parallel()
	for field, expected := range map[string]string{
		"shared_secret":                           "",
		"idp_client_secret":                       "",
		"signing_key":                             "",
		"cookie_secret":                           "",
		"autocert_eab_mac_key":                    "",
		"databroker_storage_connection_string":    "",
		"ssh_two_person_approval_request_timeout": "ssh_two_person_approval_request_timeout",
		"authenticate_service_url":                "authenticate_service_url",
		"authenticate_internal_service_url":       "service_urls",
		"scopes":                                  "idp_scopes",
		"autocert":                                "autocert",
		"ssh_user_ca_key_pair_id":                 "ssh",
		"address":                                 "address",
		"idp_provider_url":                        "idp_provider_url",
		"ssh_user_ca_key":                         "ssh",
		"certificate_authority_key_pair_id":       "certificate_authority",
		"metrics_client_secret":                   "metrics",
		"future_client_secret":                    "",
		"future_client_secret_file":               "",
		"future_private_key":                      "",
		"future_private_key_file":                 "",
		"future_host_keys":                        "",
		"future_key_pair_id":                      "future_key_pair_id",
	} {
		actual := getChangedSettingsName(field)
		assert.Equal(t, expected, actual, field)
	}
}

func mustParsePPL(t testing.TB, raw string) *config.PPLPolicy {
	ppl, err := parser.New().ParseJSON(strings.NewReader(raw))
	require.NoError(t, err)
	return &config.PPLPolicy{Policy: ppl}
}
