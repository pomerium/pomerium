package prometheus_test

import (
	"bytes"
	"io"
	"strings"
	"testing"

	"github.com/pomerium/pomerium/internal/telemetry/prometheus"
	"github.com/stretchr/testify/require"
)

// RepeatingReader repeats reading from the beginning after EOF for a specified number of times
type RepeatingReader struct {
	reader    *bytes.Reader
	resets    int
	maxResets int
}

// NewRepeatingReader creates a new reader that will reset up to maxResets times
func NewRepeatingReader(data []byte, maxResets int) *RepeatingReader {
	return &RepeatingReader{
		reader:    bytes.NewReader(data),
		resets:    0,
		maxResets: maxResets,
	}
}

// Read implements io.Reader
func (r *RepeatingReader) Read(p []byte) (n int, err error) {
	n, err = r.reader.Read(p)
	if err == io.EOF && r.resets < r.maxResets {
		r.reader.Seek(0, io.SeekStart)
		r.resets++
		return r.Read(p)
	}
	return
}

func BenchmarkRelabelTestStream(b *testing.B) {
	addLabels := map[string]string{"instance": "localhost:9090", "installation_id": "12345-67890-12345-67890"}
	src := []byte(`
# TYPE envoy_cluster_upstream_cx_total counter
envoy_cluster_upstream_cx_total{service="pomerium-proxy",envoy_cluster_name="route-1",installation_id="aecd6525-9eaa-448d-93d9-6363c04b1ccb",hostname="pomerium-proxy-55589cc5f-fjhsb"} 2
envoy_cluster_upstream_cx_total{service="pomerium-proxy",envoy_cluster_name="route-2",installation_id="aecd6525-9eaa-448d-93d9-6363c04b1ccb",hostname="pomerium-proxy-55589cc5f-fjhsb"} 3
`)

	b.Run("RelabelTextStream", func(b *testing.B) {
		inputReader := NewRepeatingReader(src, b.N)
		err := prometheus.RelabelTextStream(io.Discard, inputReader, addLabels)
		require.NoError(b, err)
	})
	b.Run("Previous", func(b *testing.B) {
		inputReader := NewRepeatingReader(src, b.N)
		err := prometheus.Export(io.Discard, prometheus.AddLabels(prometheus.NewMetricFamilyStream(inputReader), addLabels))
		require.NoError(b, err)
	})
}

func TestRelabelTextStream(t *testing.T) {
	testCases := []struct {
		name      string
		input     string
		addLabels map[string]string
		expected  string
	}{
		{
			name:      "empty input",
			input:     "",
			addLabels: map[string]string{"instance": "localhost:9090"},
			expected:  "",
		},
		{
			name:      "no labels to add",
			input:     "metric 42\n",
			addLabels: map[string]string{},
			expected:  "metric 42\n",
		},
		{
			name:      "comment lines",
			input:     "# HELP metric_name Help text\n# TYPE metric_name counter\n",
			addLabels: map[string]string{"instance": "localhost:9090"},
			expected:  "# HELP metric_name Help text\n# TYPE metric_name counter\n",
		},
		{
			name:      "metric without labels",
			input:     "http_requests_total 42\n",
			addLabels: map[string]string{"instance": "localhost:9090"},
			expected:  "http_requests_total{instance=\"localhost:9090\"} 42\n",
		},
		{
			name:      "metric with existing labels",
			input:     "http_requests_total{method=\"GET\"} 42\n",
			addLabels: map[string]string{"instance": "localhost:9090"},
			expected:  "http_requests_total{method=\"GET\",instance=\"localhost:9090\"} 42\n",
		},
		{
			name:      "multiple labels to add",
			input:     "http_requests_total 42\n",
			addLabels: map[string]string{"instance": "localhost:9090", "job": "prometheus"},
			expected:  "http_requests_total{instance=\"localhost:9090\",job=\"prometheus\"} 42\n",
		},
		{
			name:      "malformed metric (no space)",
			input:     "invalid_metric\n",
			addLabels: map[string]string{"instance": "localhost:9090"},
			expected:  "invalid_metric\n",
		},
		{
			name:      "malformed metric (no closing brace)",
			input:     "invalid_metric{label=\"value\" 42\n",
			addLabels: map[string]string{"instance": "localhost:9090"},
			expected:  "invalid_metric{label=\"value\" 42\n",
		},
		{
			name:      "empty labels",
			input:     "http_requests_total{} 42\n",
			addLabels: map[string]string{"instance": "localhost:9090"},
			expected:  "http_requests_total{instance=\"localhost:9090\"} 42\n",
		},
		{
			name:      "multiple metrics",
			input:     "metric1 10\nmetric2{label=\"value\"} 20\n# COMMENT\nmetric3 30\n",
			addLabels: map[string]string{"instance": "localhost:9090"},
			expected:  "metric1{instance=\"localhost:9090\"} 10\nmetric2{label=\"value\",instance=\"localhost:9090\"} 20\n# COMMENT\nmetric3{instance=\"localhost:9090\"} 30\n",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			inputReader := strings.NewReader(tc.input)
			outputBuffer := &bytes.Buffer{}

			err := prometheus.RelabelTextStream(outputBuffer, inputReader, tc.addLabels)
			require.NoError(t, err)

			actual := outputBuffer.String()
			require.Equal(t, tc.expected, actual)
		})
	}
}
