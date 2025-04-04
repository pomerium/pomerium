package sessions

import (
	"context"
	"fmt"
	"time"

	"go.opentelemetry.io/otel/sdk/instrumentation"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
	"golang.org/x/sync/errgroup"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/slices"
)

type Producer struct {
	scope          instrumentation.Scope
	clientProvider func() (databroker.DataBrokerServiceClient, error)
}

func NewProducer(
	scope instrumentation.Scope,
	clientProvider func() (databroker.DataBrokerServiceClient, error),
) *Producer {
	return &Producer{
		clientProvider: clientProvider,
		scope:          scope,
	}
}

func (p *Producer) Produce(ctx context.Context) ([]metricdata.ScopeMetrics, error) {
	client, err := p.clientProvider()
	if err != nil {
		return nil, fmt.Errorf("error getting client: %w", err)
	}

	now := time.Now()
	ids := []string{"dau", "mau"}
	metrics := make([]metricdata.Metrics, len(ids))
	eg, ctx := errgroup.WithContext(ctx)
	for i := 0; i < len(ids); i++ {
		eg.Go(func() error {
			state, err := LoadMetricState(ctx, client, ids[i])
			if err != nil {
				if status.Code(err) == codes.NotFound {
					return nil
				}
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

	metrics = slices.Filter(metrics, func(v metricdata.Metrics) bool { return v.Name != "" })
	if len(metrics) == 0 {
		return nil, nil
	}

	return []metricdata.ScopeMetrics{
		{
			Scope:   p.scope,
			Metrics: metrics,
		},
	}, nil
}
