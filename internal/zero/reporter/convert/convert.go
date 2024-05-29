package convert

import (
	"errors"
	"fmt"
	"io"
	"time"

	dto "github.com/prometheus/client_model/go"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
)

// FilterFn is a function that filters metric names
// returns the new metric name and true if the metric should be included
type FilterFn func(metricname string) (string, bool)

// RelabelFn is a function that relabels metric attributes
// returns the new attribute name and true if the attribute should be included
type RelabelFn func(metricname string) (string, bool)

// PrometheusToOTLP converts a prometheus metric stream to OTLP metrics
// the filter function is used to filter out unwanted metrics
// the relabel function is used to relabel metric attributes
func PrometheusToOTLP(
	src io.Reader,
	filter FilterFn,
	relabel RelabelFn,
	startTime time.Time,
	now time.Time,
) ([]metricdata.Metrics, error) {
	stream := NewMetricFamilyStream(src)
	var metrics []metricdata.Metrics
	var conversionErrors []error
	for {
		family, err := stream.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, err
		}

		name, ok := filter(family.GetName())
		if !ok {
			continue
		}

		for _, metric := range family.GetMetric() {
			data, err := convertMetric(metric, family.GetType(), relabel, startTime, now)
			if err != nil {
				conversionErrors = append(conversionErrors, fmt.Errorf("%s: %w", family.GetName(), err))
				continue
			}
			metrics = append(metrics, metricdata.Metrics{
				Data:        data,
				Description: family.GetHelp(),
				Name:        name,
				Unit:        family.GetUnit(),
			})
		}
	}

	return metrics, errors.Join(conversionErrors...)
}

func convertMetric(
	src *dto.Metric,
	typ dto.MetricType,
	relabel RelabelFn,
	startTime time.Time,
	endTime time.Time,
) (metricdata.Aggregation, error) {
	attr := convertLabels(src.GetLabel(), relabel)
	switch typ {
	case dto.MetricType_COUNTER:
		return metricdata.Sum[float64]{
			IsMonotonic: true,
			Temporality: metricdata.CumulativeTemporality,
			DataPoints: []metricdata.DataPoint[float64]{
				{
					Attributes: attr,
					StartTime:  startTime,
					Time:       endTime,
					Value:      src.GetCounter().GetValue(),
				},
			},
		}, nil
	case dto.MetricType_GAUGE:
		return metricdata.Gauge[float64]{
			DataPoints: []metricdata.DataPoint[float64]{
				{
					Attributes: attr,
					StartTime:  startTime,
					Time:       endTime,
					Value:      src.GetGauge().GetValue(),
				},
			},
		}, nil
	case dto.MetricType_HISTOGRAM:
		histogram := src.GetHistogram()
		bucket := histogram.GetBucket()
		return metricdata.Histogram[float64]{
			Temporality: metricdata.CumulativeTemporality,
			DataPoints: []metricdata.HistogramDataPoint[float64]{
				{
					Attributes:   attr,
					StartTime:    startTime,
					Time:         endTime,
					Count:        histogram.GetSampleCount(),
					Sum:          histogram.GetSampleSum(),
					Bounds:       convertBucketBounds(bucket),
					BucketCounts: convertBucketCounts(bucket),
				},
			},
		}, nil
	default:
		return nil, fmt.Errorf("unknown metric type: %s", typ)
	}
}

func convertBucketBounds(
	bucket []*dto.Bucket,
) []float64 {
	bounds := make([]float64, 0, len(bucket))
	for _, b := range bucket {
		bounds = append(bounds, b.GetUpperBound())
	}
	return bounds
}

func convertBucketCounts(
	bucket []*dto.Bucket,
) []uint64 {
	counts := make([]uint64, 0, len(bucket))
	for _, b := range bucket {
		counts = append(counts, b.GetCumulativeCount())
	}
	return counts
}

func convertLabels(
	src []*dto.LabelPair,
	relabel RelabelFn,
) attribute.Set {
	kvs := make([]attribute.KeyValue, 0, len(src))
	for _, label := range src {
		if newLabel, ok := relabel(label.GetName()); ok {
			kvs = append(kvs, attribute.String(newLabel, label.GetValue()))
		}
	}

	return attribute.NewSet(kvs...)
}
