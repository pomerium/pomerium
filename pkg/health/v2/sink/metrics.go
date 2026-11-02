package sink

import (
	"context"
	"slices"
	"strings"
	"sync"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"

	healthv2 "github.com/pomerium/pomerium/pkg/health/v2"
	"github.com/pomerium/pomerium/pkg/health/v2/check"
)

const statusErrorAttr = "error"

var allStatusAttrs = []string{
	statusAttrOf(check.StatusRunning),
	statusAttrOf(check.StatusTerminating),
	statusErrorAttr,
	statusAttrOf(check.StatusUnknown),
}

type metricKey struct {
	group check.Group
	name  check.CheckName
}

type Metrics struct {
	startTime     time.Time
	currentStatus metric.Int64Gauge
	statusCount   metric.Int64Counter
	startup       metric.Float64Gauge

	mu      sync.Mutex
	prev    map[metricKey]check.Result
	started map[metricKey]struct{}
}

var _ healthv2.HealthSink = (*Metrics)(nil)

func NewMetrics(meter metric.Meter, startTime time.Time) (*Metrics, error) {
	currentStatus, err := meter.Int64Gauge(
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
	startup, err := meter.Float64Gauge(
		"health.startup.duration",
		metric.WithUnit("s"),
		metric.WithDescription("reports the startup duration of each check"),
	)
	if err != nil {
		return nil, err
	}
	return &Metrics{
		startTime:     startTime,
		currentStatus: currentStatus,
		statusCount:   statusCount,
		startup:       startup,
		prev:          map[metricKey]check.Result{},
		started:       map[metricKey]struct{}{},
	}, nil
}

func (m *Metrics) Start() {}

func (m *Metrics) Close() {}

func (m *Metrics) Notify(snap healthv2.Snapshot) {
	m.mu.Lock()
	defer m.mu.Unlock()

	next := map[metricKey]check.Result{}
	for _, c := range snap.Checkers {
		for _, r := range c.Results {
			if r.Reported() {
				next[metricKey{c.Group, r.Name}] = r
			}
		}
	}
	for key, prev := range m.prev {
		if r, ok := next[key]; !ok || !slices.Equal(r.Attrs, prev.Attrs) {
			m.resetStatusLocked(metricAttrs(key.group, prev))
		}
	}
	for key, r := range next {
		if prev, ok := m.prev[key]; ok && prev.Equal(r) {
			continue
		}
		m.recordLocked(key, r)
	}
	m.prev = next
}

func (m *Metrics) recordLocked(key metricKey, r check.Result) {
	ctx := context.Background()
	attrs := metricAttrs(key.group, r)
	current := statusAttr(r)

	m.statusCount.Add(ctx, 1, withStatus(attrs, current))
	m.recordStatusLocked(attrs, current)

	if _, ok := m.started[key]; !ok && r.Status != check.StatusUnknown {
		m.started[key] = struct{}{}
		m.startup.Record(ctx, time.Since(m.startTime).Seconds(), metric.WithAttributeSet(attribute.NewSet(attrs...)))
	}
}

func (m *Metrics) recordStatusLocked(attrs []attribute.KeyValue, current string) {
	for _, st := range allStatusAttrs {
		var v int64
		if st == current {
			v = 1
		}
		m.currentStatus.Record(context.Background(), v, withStatus(attrs, st))
	}
}

func (m *Metrics) resetStatusLocked(attrs []attribute.KeyValue) {
	m.recordStatusLocked(attrs, "")
}

func metricAttrs(group check.Group, r check.Result) []attribute.KeyValue {
	attrs := make([]attribute.KeyValue, 0, len(r.Attrs)+2)
	for _, a := range r.Attrs {
		attrs = append(attrs, attribute.String(a.Key, a.Value))
	}
	return append(attrs,
		attribute.String("check", string(r.Name)),
		attribute.String("group", string(group)),
	)
}

func statusAttr(r check.Result) string {
	if r.Err != nil {
		return statusErrorAttr
	}
	return statusAttrOf(r.Status)
}

func statusAttrOf(s check.Status) string {
	return strings.ToLower(s.String())
}

func withStatus(attrs []attribute.KeyValue, status string) metric.MeasurementOption {
	return metric.WithAttributeSet(attribute.NewSet(append(attrs[:len(attrs):len(attrs)], attribute.String("status", status))...))
}
