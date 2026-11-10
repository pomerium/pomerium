package healthtest

import (
	"slices"
	"sync"
	"testing"
	"uuid"

	"github.com/pomerium/pomerium/pkg/health"
)

const (
	healthAttrTest = "test-id"
)

func HealhAttrTest(uuid string) health.Attr {
	return health.StrAttr(healthAttrTest, uuid)
}

type HealthStatus struct {
	Check      health.Check
	Status     health.Status
	Attributes []health.Attr
}

type HealthError struct {
	check      health.Check
	err        error
	attributes []health.Attr
}

type HealthTester interface {
	// returns the UUID this temporary tracker was registered for
	GetUUID() string
	GetStatuses(check health.Check) []HealthStatus
	GetErrors(check health.Check) []HealthError
}

type healthTrackerPerTest struct {
	healthID string /* filter for test-generated uuid */
	mu       sync.Mutex
	statuses []HealthStatus
	errors   []HealthError
}

// NewTrackerForTest registers a new health.Provider with a new uuid,
// and only tracks health checks with the `test-id=<uuid>` attribute.
// Returns a subset of the tracker that fetches reported statuses/errors
func NewTrackerForTest(t *testing.T) HealthTester {
	id := uuid.New().String()
	mgr := health.GetProviderManager()
	tracker := &healthTrackerPerTest{
		healthID: id,
	}
	mgr.Register(health.ProviderID(id), tracker)
	t.Cleanup(func() {
		mgr.Deregister(health.ProviderID(id))
	})
	return tracker
}

func (t *healthTrackerPerTest) GetUUID() string {
	return t.healthID
}

func (t *healthTrackerPerTest) GetErrors(check health.Check) []HealthError {
	t.mu.Lock()
	defer t.mu.Unlock()
	var s []HealthError
	for _, el := range t.errors {
		if el.check == check {
			s = append(s, el)
		}
	}
	return s
}

func (t *healthTrackerPerTest) GetStatuses(check health.Check) []HealthStatus {
	t.mu.Lock()
	defer t.mu.Unlock()
	var s []HealthStatus
	for _, el := range t.statuses {
		if el.Check == check {
			s = append(s, el)
		}
	}
	return s
}

func (t *healthTrackerPerTest) ReportError(check health.Check, err error, attributes ...health.Attr) {
	if !slices.Contains(attributes, health.StrAttr(healthAttrTest, t.healthID)) {
		return
	}
	t.mu.Lock()
	t.errors = append(t.errors, HealthError{check, err, attributes})
	t.mu.Unlock()
}

func (t *healthTrackerPerTest) ReportStatus(check health.Check, status health.Status, attributes ...health.Attr) {
	if !slices.Contains(attributes, health.StrAttr(healthAttrTest, t.healthID)) {
		return
	}
	t.mu.Lock()
	t.statuses = append(t.statuses, HealthStatus{check, status, attributes})
	t.mu.Unlock()
}
