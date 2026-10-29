package analytics

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"strings"
	"testing"

	"github.com/posthog/posthog-go"
	"github.com/shirou/gopsutil/v4/cpu"
	"github.com/shirou/gopsutil/v4/host"
	"github.com/shirou/gopsutil/v4/mem"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/pkg/cryptutil"
	configpb "github.com/pomerium/pomerium/pkg/grpc/config"
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
		"cpu_core_count": 2,
		"cpu_count":      2,
		"cpu_family":     "6",
		"cpu_model":      "197",
		"cpu_model_name": "Intel(R) Core(TM) Ultra 9 285H",
		"cpu_vendor_id":  "GenuineIntel",
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
		"kernel_version":        "7.0.0-38-generic",
		"os":                    "linux",
		"platform":              "ubuntu",
		"platform_family":       "debian",
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
		"mem_available_gib": 6.,
		"mem_total_gib":     32.,
		"mem_used_gib":      25.,
	}, p)
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
			})
	}
	p := New().(*reporter).CreatePosthogPropertiesForRoutes(cfg)
	assert.Equal(t, posthog.Properties{
		"route_count": 600.,
		"route_types": map[string]any{
			"http":       100.,
			"kubernetes": 100.,
			"mcp_server": 100.,
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
		"policy_count": 5.,
		"ppl_criteria": map[string]any{
			"accept":             2.,
			"authenticated_user": 1.,
			"domain":             2.,
			"email":              1.,
			"user":               1.,
		},
		"ppl_operators": map[string]any{
			"and": 1.,
			"nor": 2.,
			"not": 0.,
			"or":  8.,
		},
		"shared_policy_count": 1.,
	}, p)
}

func TestCreatePosthogPropertiesForSettings(t *testing.T) {
	t.Parallel()
	cfg := &config.Config{Options: config.NewDefaultOptions()}
	cfg.Options.SharedKey = base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0xAA}, 32))
	p := New().(*reporter).CreatePosthogPropertiesForSettings(cfg)
	assert.Equal(t, posthog.Properties{
		"databroker_storage_type":            "memory",
		"identity_provider":                  "none",
		"log_level":                          "info",
		"originator_id":                      "local",
		"proxy_log_level":                    "",
		"pseudonymous_identity_provider_url": "oiGhP9PrJsKGVL8bD4erGKflPjDy6zhgWYwqYXuJLaQ=",
		"services":                           "all",
	}, p)
}

func mustParsePPL(t testing.TB, raw string) *config.PPLPolicy {
	ppl, err := parser.New().ParseJSON(strings.NewReader(raw))
	require.NoError(t, err)
	return &config.PPLPolicy{Policy: ppl}
}
