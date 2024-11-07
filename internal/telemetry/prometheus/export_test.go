package prometheus_test

import (
	"bytes"
	_ "embed"
	"io"
	"iter"
	"testing"

	"github.com/google/go-cmp/cmp"
	dto "github.com/prometheus/client_model/go"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"

	"github.com/pomerium/pomerium/internal/telemetry/prometheus"
)

//go:embed testdata/large.txt
var exportTestData []byte

func BenchmarkExport(b *testing.B) {
	r := bytes.NewReader(exportTestData)
	err := prometheus.Export(io.Discard,
		prometheus.AddLabels(prometheus.NewMetricFamilyStream(r),
			map[string]string{"installation_id": "abc1231-1231-1231-1231-1231", "hostname": "ec2-1231-1231-1231-1231-1231.us-west-2.compute.amazonaws.com"},
		))
	require.NoError(b, err)
}

func TestExport(t *testing.T) {
	it := func(data []*dto.MetricFamily) iter.Seq2[*dto.MetricFamily, error] {
		return func(yield func(*dto.MetricFamily, error) bool) {
			for _, mf := range data {
				if !yield(mf, nil) {
					return
				}
			}
		}
	}

	tests := []struct {
		name     string
		expected string
		input    []*dto.MetricFamily
	}{
		{
			name: "single metric family",
			expected: `# HELP http_requests_total The total number of HTTP requests.
# TYPE http_requests_total counter
http_requests_total{method="post",code="200"} 1027 1395066363000
`,
			input: []*dto.MetricFamily{
				{
					Name: proto.String("http_requests_total"),
					Help: proto.String("The total number of HTTP requests."),
					Type: dto.MetricType_COUNTER.Enum(),
					Metric: []*dto.Metric{
						{
							Label: []*dto.LabelPair{
								{Name: proto.String("method"), Value: proto.String("post")},
								{Name: proto.String("code"), Value: proto.String("200")},
							},
							Counter:     &dto.Counter{Value: proto.Float64(1027)},
							TimestampMs: proto.Int64(1395066363000),
						},
					},
				},
			},
		},
		{
			name: "multiple metric families",
			expected: `# TYPE http_requests_total counter
http_requests_total{method="post",code="200"} 1027 1395066363000
# TYPE cpu_seconds_total counter
cpu_seconds_total 12345.6
`,
			input: []*dto.MetricFamily{
				{
					Name: proto.String("http_requests_total"),
					Type: dto.MetricType_COUNTER.Enum(),
					Metric: []*dto.Metric{
						{
							Label: []*dto.LabelPair{
								{Name: proto.String("method"), Value: proto.String("post")},
								{Name: proto.String("code"), Value: proto.String("200")},
							},
							Counter:     &dto.Counter{Value: proto.Float64(1027)},
							TimestampMs: proto.Int64(1395066363000),
						},
					},
				},
				{
					Name: proto.String("cpu_seconds_total"),
					Type: dto.MetricType_COUNTER.Enum(),
					Metric: []*dto.Metric{
						{
							Counter: &dto.Counter{Value: proto.Float64(12345.6)},
						},
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var w bytes.Buffer
			err := prometheus.Export(&w, it(tt.input))
			require.NoError(t, err)
			got := w.String()
			t.Log(got)
			diff := cmp.Diff(tt.expected, got)
			require.Empty(t, diff)
		})
	}
}
