package prometheus_test

import (
	"embed"
	"math"
	"path"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"

	"github.com/pomerium/pomerium/internal/zero/telemetry/prometheus"
)

//go:embed testdata
var testdata embed.FS

func TestConvert(t *testing.T) {
	t.Parallel()

	start, err := time.Parse(time.RFC3339, "2024-05-29T00:00:01Z")
	require.NoError(t, err)
	end, err := time.Parse(time.RFC3339, "2021-05-29T01:00:00Z")
	require.NoError(t, err)

	cases := []struct {
		name string
		want []metricdata.Metrics
	}{
		{
			"histogram",
			[]metricdata.Metrics{
				{
					Name: "envoy_cluster_upstream_rq_time",
					Data: metricdata.Histogram[float64]{
						Temporality: metricdata.CumulativeTemporality,
						DataPoints: []metricdata.HistogramDataPoint[float64]{
							{
								Attributes: attribute.NewSet(
									attribute.String("pomerium_route_id", "metrics-00083"),
								),
								StartTime:    start,
								Time:         end,
								Count:        2,
								Sum:          4.1,
								Bounds:       []float64{0.5, 1, 5, 10, 25, 50, 100, 250, 500, 1000, 2500, 5000, 10000, 30000, 60000, 300000, 600000, 1800000, 3600000, math.Inf(1)},
								BucketCounts: []uint64{0, 0, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2},
							},
						},
					},
				},
			},
		},
		{
			"counter",
			[]metricdata.Metrics{
				{
					Name: "envoy_cluster_upstream_cx_total",
					Data: metricdata.Sum[float64]{
						IsMonotonic: true,
						Temporality: metricdata.CumulativeTemporality,
						DataPoints: []metricdata.DataPoint[float64]{
							{
								Attributes: attribute.NewSet(
									attribute.String("pomerium_route_id", "route-1"),
								),
								Value:     2,
								StartTime: start,
								Time:      end,
							},
						},
					},
				},
				{
					Name: "envoy_cluster_upstream_cx_total",
					Data: metricdata.Sum[float64]{
						IsMonotonic: true,
						Temporality: metricdata.CumulativeTemporality,
						DataPoints: []metricdata.DataPoint[float64]{
							{
								Attributes: attribute.NewSet(
									attribute.String("pomerium_route_id", "route-2"),
								),
								Value:     3,
								StartTime: start,
								Time:      end,
							},
						},
					},
				},
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			fd, err := testdata.Open(path.Join("testdata", tc.name+".txt"))
			require.NoError(t, err)
			defer fd.Close()

			got, err := prometheus.ToOTLP(fd,
				func(name string) (string, bool) {
					return name, true
				}, func(label string) (string, bool) {
					if label == "envoy_cluster_name" {
						return "pomerium_route_id", true
					}
					return "", false
				}, start, end)
			require.NoError(t, err)
			assert.Empty(t, cmp.Diff(tc.want, got, cmpopts.IgnoreUnexported(
				attribute.Set{},
				metricdata.Extrema[float64]{},
			),
				cmp.Comparer(compareAttributeSets),
			))
		})
	}
}

func compareAttributeSets(x, y attribute.Set) bool {
	if x.Len() != y.Len() {
		return false
	}
	for _, kv := range x.ToSlice() {
		if v, found := y.Value(kv.Key); !found || v != kv.Value {
			return false
		}
	}
	return true
}
