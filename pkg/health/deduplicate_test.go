package health_test

import (
	"errors"
	"testing"

	"go.uber.org/mock/gomock"

	health "github.com/pomerium/pomerium/pkg/health"
)

//go:generate go run go.uber.org/mock/mockgen -package health_test -destination provider_mock_test.go github.com/pomerium/pomerium/pkg/health Provider

func TestDeduplicate(t *testing.T) {
	t.Parallel()
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	p1 := NewMockProvider(ctrl)
	dp := health.NewDeduplicator()
	dp.SetProvider(p1)

	check1, check2, check3 := health.Check("check-1"), health.Check("check-2"), health.Check("check-3")
	p1.EXPECT().ReportStatus(check1, health.StatusRunning).Times(1)
	p1.EXPECT().ReportStatus(check2, health.StatusRunning).Times(1)
	p1.EXPECT().ReportError(check3, errors.New("error-3")).Times(1)
	dp.ReportStatus(check1, health.StatusRunning)
	dp.ReportStatus(check2, health.StatusRunning)
	dp.ReportStatus(check1, health.StatusRunning)
	dp.ReportError(check3, errors.New("error-3"))

	p1.EXPECT().ReportError(check1, errors.New("error")).Times(1)
	dp.ReportError(check1, errors.New("error"))
	dp.ReportError(check1, errors.New("error"))

	p1.EXPECT().ReportStatus(check1, health.StatusRunning).Times(1)
	dp.ReportStatus(check1, health.StatusRunning)

	p1.EXPECT().ReportStatus(check1, health.StatusRunning, health.StrAttr("k1", "v1")).Times(2)
	p1.EXPECT().ReportStatus(check1, health.StatusRunning, health.StrAttr("k1", "v2")).Times(1)
	dp.ReportStatus(check1, health.StatusRunning, health.StrAttr("k1", "v1"))
	dp.ReportStatus(check1, health.StatusRunning, health.StrAttr("k1", "v2"))
	dp.ReportStatus(check1, health.StatusRunning, health.StrAttr("k1", "v1"))

	// after setting new provider, current state should be reported
	p2 := NewMockProvider(ctrl)
	p2.EXPECT().ReportStatus(check1, health.StatusRunning, health.StrAttr("k1", "v1")).Times(1)
	p2.EXPECT().ReportStatus(check2, health.StatusRunning).Times(1)
	p2.EXPECT().ReportError(check3, errors.New("error-3")).Times(1)
	dp.SetProvider(p2)
}
