package sessions

import (
	"context"
	"fmt"
	"time"

	"go.opentelemetry.io/otel/sdk/instrumentation"
	"go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
	"golang.org/x/sync/errgroup"

	"github.com/pomerium/pomerium/pkg/grpc/databroker"
)

type producer struct {
	scope          instrumentation.Scope
	clientProvider func() (databroker.DataBrokerServiceClient, error)
}

func NewProducer(
	scope instrumentation.Scope,
	clientProvider func() (databroker.DataBrokerServiceClient, error),
) metric.Producer {
	return &producer{
		clientProvider: clientProvider,
		scope:          scope,
	}
}

func (p *producer) Produce(ctx context.Context) ([]metricdata.ScopeMetrics, error) {
	client, err := p.clientProvider()
	if err != nil {
		return nil, fmt.Errorf("error getting client: %w", err)
	}

	now := time.Now()
	ids := []string{"dau", "mau"}
	metrics := make([]metricdata.Metrics, len(ids))
	eg, ctx := errgroup.WithContext(ctx)
	for i := 0; i < len(ids); i++ {
		i := i
		eg.Go(func() error {
			state, err := LoadMetricState(ctx, client, ids[i])
			if err != nil {
				return err
			}
			metrics[i] = metricdata.Metrics{
				Name: ids[i],
				Unit: "unique users",
				Data: metricdata.Gauge[int64]{
					DataPoints: []metricdata.DataPoint[int64]{
						{
							Time:  now,
							Value: int64(state.Count),
						},
					},
				},
			}
			return nil
		})
	}

	err = eg.Wait()
	if err != nil {
		return nil, err
	}

	return []metricdata.ScopeMetrics{
		{
			Scope:   p.scope,
			Metrics: metrics,
		},
	}, nil
}
