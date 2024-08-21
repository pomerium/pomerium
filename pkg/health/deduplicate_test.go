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

	p1 := NewMockProvider(gomock.NewController(t))
	dp := health.NewDeduplicator()
	dp.SetProvider(p1)

	check1, check2, check3 := health.Check("check-1"), health.Check("check-2"), health.Check("check-3")
	p1.EXPECT().ReportOK(check1).Times(1)
	p1.EXPECT().ReportOK(check2).Times(1)
	p1.EXPECT().ReportError(check3, errors.New("error-3")).Times(1)
	dp.ReportOK(check1)
	dp.ReportOK(check2)
	dp.ReportOK(check1)
	dp.ReportError(check3, errors.New("error-3"))

	p1.EXPECT().ReportError(check1, errors.New("error")).Times(1)
	dp.ReportError(check1, errors.New("error"))
	dp.ReportError(check1, errors.New("error"))

	p1.EXPECT().ReportOK(check1).Times(1)
	dp.ReportOK(check1)

	p1.EXPECT().ReportOK(check1, health.StrAttr("k1", "v1")).Times(2)
	p1.EXPECT().ReportOK(check1, health.StrAttr("k1", "v2")).Times(1)
	dp.ReportOK(check1, health.StrAttr("k1", "v1"))
	dp.ReportOK(check1, health.StrAttr("k1", "v2"))
	dp.ReportOK(check1, health.StrAttr("k1", "v1"))

	// after setting new provider, current state should be reported
	p2 := NewMockProvider(gomock.NewController(t))
	p2.EXPECT().ReportOK(check1, health.StrAttr("k1", "v1")).Times(1)
	p2.EXPECT().ReportOK(check2).Times(1)
	p2.EXPECT().ReportError(check3, errors.New("error-3")).Times(1)
	dp.SetProvider(p2)
}

func TestDefault(t *testing.T) {
	t.Parallel()

	p := NewMockProvider(gomock.NewController(t))
	health.SetProvider(p)

	check1 := health.Check("check-1")
	p.EXPECT().ReportOK(check1).Times(1)
	health.ReportOK(check1)

	health.SetProvider(nil)
	health.ReportOK(check1)
}
