package controlplane

import (
	"slices"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/pkg/health"
)

func TestExpectedHealthChecksIncludePostgresOnlyWhenRunnable(t *testing.T) {
	tests := []struct {
		name     string
		services string
		address  string
		enabled  bool
		want     bool
	}{
		{"all services enabled", config.ServiceAll, "127.0.0.1:5432", true, true},
		{"flag disabled", config.ServiceAll, "127.0.0.1:5432", false, false},
		{"address absent", config.ServiceAll, "", true, false},
		{"proxy without authorize", config.ServiceProxy, "127.0.0.1:5432", true, false},
		{"authorize without proxy", config.ServiceAuthorize, "127.0.0.1:5432", true, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			opts := config.NewDefaultOptions()
			opts.Services = tc.services
			opts.PostgresAddr = tc.address
			opts.RuntimeFlags[config.RuntimeFlagPostgres] = tc.enabled
			checks := new(Server).getExpectedHealthChecks(config.New(opts))
			require.Equal(t, tc.want, slices.Contains(checks, health.PostgresListener))
		})
	}
}
