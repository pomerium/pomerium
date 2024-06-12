package prometheus_test

import (
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	dto "github.com/prometheus/client_model/go"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/testing/protocmp"

	"github.com/pomerium/pomerium/internal/telemetry/prometheus"
)

func TestMetricFamilyStream(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected []*dto.MetricFamily
		wantErr  bool
	}{
		{
			name: "single metric family",
			input: `
# HELP http_requests_total The total number of HTTP requests.
# TYPE http_requests_total counter
http_requests_total{method="post",code="200"} 1027 1395066363000
`,
			expected: []*dto.MetricFamily{
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
			wantErr: false,
		},
		{
			name: "multiple metric families",
			input: `
# TYPE http_requests_total counter
http_requests_total{method="post",code="200"} 1027 1395066363000
# TYPE cpu_seconds_total counter
cpu_seconds_total 12345.6
`,
			expected: []*dto.MetricFamily{
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
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reader := strings.NewReader(tt.input)
			metricStream := prometheus.NewMetricFamilyStream(reader)

			var got []*dto.MetricFamily
			for {
				mf, err := metricStream.Next()
				if errors.Is(err, io.EOF) {
					break
				}
				if (err != nil) != tt.wantErr {
					t.Errorf("MetricFamilyStream.Next() error = %v, wantErr %v", err, tt.wantErr)
					return
				}
				if err == nil {
					got = append(got, mf)
				}
			}

			diff := cmp.Diff(tt.expected, got, protocmp.Transform(), cmpopts.IgnoreUnexported(dto.MetricFamily{}, dto.Metric{}, dto.LabelPair{}, dto.Counter{}))
			require.Empty(t, diff)
		})
	}
}
