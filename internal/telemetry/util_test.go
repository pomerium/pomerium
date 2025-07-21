package telemetry

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_ServiceName(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name        string
		servicesOpt string
		want        string
	}{
		{"all", "all", "pomerium"},
		{"proxy", "proxy", "pomerium-proxy"},
		{"missing", "", "pomerium"},
		{"multiple", "authorize,proxy", "pomerium"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, ServiceName(tt.servicesOpt))
		})
	}
}
