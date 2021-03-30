package registry

import (
	"testing"

	"github.com/pomerium/pomerium/config"
	"github.com/stretchr/testify/assert"
)

func TestMetricsURL(t *testing.T) {
	for opt, expect := range map[*config.Options]string{
		{MetricsAddr: "my.host:9090"}: "http://my.host:9090/metrics",
		{MetricsAddr: "my.host:9090", MetricsBasicAuth: "bXl1c2VyOm15cGFzc3dvcmQ="}: "http://myuser:mypassword@my.host:9090/metrics",
		{MetricsAddr: "my.host:9090", MetricsCertificate: "CERT"}:                   "https://my.host:9090/metrics",
		{MetricsAddr: "my.host:9090", MetricsCertificateFile: "CERT"}:               "https://my.host:9090/metrics",
	} {
		u, err := metricsURL(*opt)
		if assert.NoError(t, err, opt) {
			assert.Equal(t, expect, u.String())
		}
	}

	for _, opt := range []config.Options{
		{MetricsAddr: "my.host:"},
		{MetricsAddr: "my.host:9090", MetricsBasicAuth: "SMTH"},
		{MetricsAddr: ":9090"},
		{MetricsAddr: "my.host"},
	} {
		_, err := metricsURL(opt)
		assert.Error(t, err, opt)
	}
}
