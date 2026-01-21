package health

import (
	"context"
	"fmt"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"

	"github.com/pomerium/pomerium/pkg/slices"
)

const statusErrorAttr = "error"

type Metrics struct {
	// HealthCurrentStatus tracks the current status of each health check. One of `running`, `terminating`, `error` or `unknown`
	HealthCurrentStatus metric.Int64Gauge
	// HealthStatusCount tracks the total number of states reported by each check
	HealthStatusCount metric.Int64Counter
	// HealthStartupDurationSeconds reports the startup duration of each check
	HealthStartupDurationSeconds metric.Float64Gauge
}

func NewMetrics(meter metric.Meter) (*Metrics, error) {
	curStatus, err := meter.Int64Gauge(
		"health.status",
		metric.WithDescription("tracks the current status of each health check. One of `running`, `terminating`, `error` or `unknown`"),
	)
	if err != nil {
		return nil, err
	}

	statusCount, err := meter.Int64Counter(
		"health.status.total",
		metric.WithDescription("tracks the total number of states reported by each check"),
	)
	if err != nil {
		return nil, err
	}

	startupDur, err := meter.Float64Gauge(
		"health.startup.duration",
		metric.WithUnit("s"),
		metric.WithDescription("reports the startup duration of each check"),
	)
	if err != nil {
		return nil, err
	}
	return &Metrics{
		HealthCurrentStatus:          curStatus,
		HealthStatusCount:            statusCount,
		HealthStartupDurationSeconds: startupDur,
	}, nil
}

type MetricsProvider struct {
	parentCtx context.Context
	*Metrics
	tr        Tracker
	startTime time.Time
}

func NewMetricsProvider(
	parentCtx context.Context,
	metrics *Metrics,
	tr Tracker,
	startTime time.Time,
) *MetricsProvider {
	return &MetricsProvider{
		parentCtx: parentCtx,
		Metrics:   metrics,
		tr:        tr,
		startTime: startTime,
	}
}

var _ Provider = (*MetricsProvider)(nil)

func attributeSet(els []Attr, additionalAttrs ...attribute.KeyValue) []attribute.KeyValue {
	ret := slices.Map(els, func(a Attr) attribute.KeyValue {
		return a.AsOtelAttribute()
	})
	ret = append(ret, additionalAttrs...)
	return ret
}

func notReported(status Status, err error) []string {
	if err != nil {
		return []string{StatusRunning.AsAttr(), StatusTerminating.AsAttr(), StatusUnknown.AsAttr()}
	}
	switch status {
	case StatusRunning:
		return []string{StatusTerminating.AsAttr(), statusErrorAttr, StatusUnknown.AsAttr()}
	case StatusTerminating:
		return []string{StatusRunning.AsAttr(), statusErrorAttr, StatusUnknown.AsAttr()}
	case StatusUnknown:
		return []string{StatusRunning.AsAttr(), StatusTerminating.AsAttr(), statusErrorAttr}
	default:
		panic(fmt.Sprintf("unhandled : status \" %s \" in metric reporting", status.AsAttr()))
	}
}

func (m *MetricsProvider) reportCurrentStatus(
	status Status,
	err error,
	attributes []attribute.KeyValue,
) {
	var curStatus string
	if err != nil {
		curStatus = statusErrorAttr
	} else {
		curStatus = status.AsAttr()
	}

	m.HealthCurrentStatus.Record(
		m.parentCtx,
		1,
		metric.WithAttributeSet(
			attribute.NewSet(
				append(
					attributes,
					attribute.String("status", curStatus),
				)...,
			),
		),
	)

	for _, status := range notReported(status, err) {
		m.HealthCurrentStatus.Record(
			m.parentCtx,
			0,
			metric.WithAttributeSet(
				attribute.NewSet(
					append(
						attributes,
						attribute.String("status", status),
					)...,
				),
			),
		)
	}
}

func (m *MetricsProvider) ReportStatus(check Check, status Status, attributes ...Attr) {
	commonAttr := attributeSet(
		attributes,
		attribute.String("check", string(check)),
	)

	if m.tr.HasStarted(check) {
		startTime := time.Since(m.startTime).Seconds()
		m.HealthStartupDurationSeconds.Record(
			m.parentCtx,
			startTime,
			metric.WithAttributeSet(
				attribute.NewSet(commonAttr...),
			),
		)
	}

	m.reportCurrentStatus(status, nil, commonAttr)

	m.HealthStatusCount.Add(m.parentCtx, 1, metric.WithAttributeSet(
		attribute.NewSet(
			append(
				commonAttr,
				attribute.String("status", status.AsAttr()),
			)...,
		),
	))
}

func (m *MetricsProvider) ReportError(check Check, err error, attributes ...Attr) {
	commonAttr := attributeSet(
		attributes,
		attribute.String("check", string(check)),
	)
	m.HealthStatusCount.Add(m.parentCtx, 1, metric.WithAttributeSet(
		attribute.NewSet(
			append(
				commonAttr,
				attribute.String("status", statusErrorAttr),
			)...,
		),
	))

	m.reportCurrentStatus(StatusUnknown, err, commonAttr)
}
