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
)

const statusTerminating = "terminating"

var allStatuses = []string{
	stateStatus(healthv2.StateOK),
	stateStatus(healthv2.StateStarting),
	stateStatus(healthv2.StateNotReady),
	stateStatus(healthv2.StateUnhealthy),
	statusTerminating,
}

type metricKey struct {
	service healthv2.ServiceID
	name    string
}

type Metrics struct {
	startTime     time.Time
	currentStatus metric.Int64Gauge
	statusCount   metric.Int64Counter
	startup       metric.Float64Gauge

	mu           sync.Mutex
	prev         map[metricKey]healthv2.State
	started      map[metricKey]struct{}
	shuttingDown bool
}

var _ healthv2.HealthSink = (*Metrics)(nil)

func NewMetrics(meter metric.Meter, startTime time.Time) (*Metrics, error) {
	currentStatus, err := meter.Int64Gauge(
		"health.status",
		metric.WithDescription("tracks the current status of each health checker. One of `ok`, `starting`, `not_ready`, `unhealthy` or `terminating`"),
	)
	if err != nil {
		return nil, err
	}
	statusCount, err := meter.Int64Counter(
		"health.status.total",
		metric.WithDescription("tracks the total number of states reported by each checker"),
	)
	if err != nil {
		return nil, err
	}
	startup, err := meter.Float64Gauge(
		"health.startup.duration",
		metric.WithUnit("s"),
		metric.WithDescription("reports the time until each checker is first initialized"),
	)
	if err != nil {
		return nil, err
	}
	return &Metrics{
		startTime:     startTime,
		currentStatus: currentStatus,
		statusCount:   statusCount,
		startup:       startup,
		prev:          map[metricKey]healthv2.State{},
		started:       map[metricKey]struct{}{},
	}, nil
}

func (m *Metrics) Run() {}

func (m *Metrics) Notify(snap healthv2.Snapshot) {
	m.mu.Lock()
	defer m.mu.Unlock()

	for _, c := range snap.Checkers {
		key := metricKey{c.Service, c.Name}
		state := c.State()
		if m.statusChangedLocked(key, state) {
			m.recordStatusLocked(context.Background(), key, m.statusLocked(state))
		}
		m.prev[key] = state
		if m.firstInitializedLocked(key, c) {
			m.started[key] = struct{}{}
			m.startup.Record(context.Background(), time.Since(m.startTime).Seconds(), metric.WithAttributeSet(attribute.NewSet(metricAttrs(key)...)))
		}
	}
}

// Shutdown reports every checker as terminating in health.status, except an
// unhealthy checker, which keeps reporting unhealthy. It does not block, has an
// effect only on the first call, and is safe to call concurrently with Notify.
func (m *Metrics) Shutdown(ctx context.Context) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.shuttingDown {
		return
	}
	m.shuttingDown = true
	ctx = context.WithoutCancel(ctx)
	for key, state := range m.prev {
		if status := m.statusLocked(state); status != stateStatus(state) {
			m.recordStatusLocked(ctx, key, status)
		}
	}
}

func (m *Metrics) statusChangedLocked(key metricKey, state healthv2.State) bool {
	prev, ok := m.prev[key]
	return !ok || m.statusLocked(prev) != m.statusLocked(state)
}

func (m *Metrics) statusLocked(state healthv2.State) string {
	if m.shuttingDown && state != healthv2.StateUnhealthy {
		return statusTerminating
	}
	return stateStatus(state)
}

func (m *Metrics) firstInitializedLocked(key metricKey, c healthv2.CheckerStatus) bool {
	_, started := m.started[key]
	return !started && c.Initialized.OK
}

func (m *Metrics) recordStatusLocked(ctx context.Context, key metricKey, current string) {
	attrs := metricAttrs(key)
	m.statusCount.Add(ctx, 1, withStatus(attrs, current))
	for _, status := range allStatuses {
		var v int64
		if status == current {
			v = 1
		}
		m.currentStatus.Record(ctx, v, withStatus(attrs, status))
	}
}

func stateStatus(state healthv2.State) string {
	return strings.ToLower(state.String())
}

func metricAttrs(key metricKey) []attribute.KeyValue {
	return []attribute.KeyValue{
		attribute.String("group", string(key.service)),
		attribute.String("checker", key.name),
	}
}

func withStatus(attrs []attribute.KeyValue, status string) metric.MeasurementOption {
	return metric.WithAttributeSet(attribute.NewSet(append(slices.Clip(attrs), attribute.String("status", status))...))
}
