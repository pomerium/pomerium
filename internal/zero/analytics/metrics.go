package analytics

import (
	"context"

	"go.opentelemetry.io/otel/metric"

	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/pkg/grpc/databroker"
)

// Metrics returns a list of metrics to be exported
func Metrics(
	clientProvider func() databroker.DataBrokerServiceClient,
) []func(m metric.Meter) error {
	return []func(m metric.Meter) error{
		registerMetric("dau", clientProvider),
		registerMetric("mau", clientProvider),
	}
}

func registerMetric(
	id string,
	clientProvider func() databroker.DataBrokerServiceClient,
) func(m metric.Meter) error {
	return func(m metric.Meter) error {
		_, err := m.Int64ObservableGauge(id,
			metric.WithInt64Callback(metricCallback(id, clientProvider)),
		)
		return err
	}
}

func metricCallback(
	id string,
	clientProvider func() databroker.DataBrokerServiceClient,
) metric.Int64Callback {
	return func(ctx context.Context, result metric.Int64Observer) error {
		state, err := LoadMetricState(context.Background(), clientProvider(), id)
		if err != nil {
			log.Ctx(ctx).Error().Err(err).Str("metric", id).Msg("error loading metric state")
			return nil // returning an error would block export of other metrics
		}
		result.Observe(int64(state.Count))
		return nil
	}
}
