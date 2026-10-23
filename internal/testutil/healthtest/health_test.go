package healthtest

import (
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"

	"github.com/pomerium/pomerium/pkg/health"
)

func TestHealthTest(t *testing.T) {
	tracker := NewTrackerForTest(t)

	statusCheck := health.Check("healthtest.status")
	errorCheck := health.Check("healthtest.error")
	otherCheck := health.Check("healthtest.other")
	errTest := errors.New("test")

	health.ReportStatus(statusCheck, health.StatusRunning, HealhAttrTest(tracker.GetUUID()))
	health.ReportError(errorCheck, errTest, HealhAttrTest(tracker.GetUUID()))
	health.ReportStatus(otherCheck, health.StatusRunning, HealhAttrTest(uuid.NewString()))
	health.ReportError(otherCheck, errTest)

	assert.Equal(t, []HealthStatus{
		{statusCheck, health.StatusRunning, []health.Attr{HealhAttrTest(tracker.GetUUID())}},
	}, tracker.GetStatuses(statusCheck))
	assert.Equal(t, []HealthError{
		{errorCheck, errTest, []health.Attr{HealhAttrTest(tracker.GetUUID())}},
	}, tracker.GetErrors(errorCheck))
	assert.Empty(t, tracker.GetStatuses(errorCheck))
	assert.Empty(t, tracker.GetErrors(statusCheck))
	assert.Empty(t, tracker.GetStatuses(otherCheck))
	assert.Empty(t, tracker.GetErrors(otherCheck))
}
