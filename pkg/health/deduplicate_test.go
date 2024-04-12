package health_test

import (
	"errors"
	"testing"

	"github.com/golang/mock/gomock"

	health "github.com/pomerium/pomerium/pkg/health"
)

//go:generate go run github.com/golang/mock/mockgen -package health_test -destination provider_mock_test.go github.com/pomerium/pomerium/pkg/health Provider

func TestDeduplicate(t *testing.T) {
	t.Parallel()

	p := NewMockProvider(gomock.NewController(t))
	dp := health.NewDeduplicator(p)

	check1, check2 := health.Check("check-1"), health.Check("check-2")
	p.EXPECT().ReportOK(check1).Times(1)
	p.EXPECT().ReportOK(check2).Times(1)
	dp.ReportOK(check1)
	dp.ReportOK(check2)
	dp.ReportOK(check1)

	p.EXPECT().ReportError(check1, gomock.Any()).Times(1)
	dp.ReportError(check1, errors.New("error"))
	dp.ReportError(check1, errors.New("error"))

	p.EXPECT().ReportOK(check1).Times(1)
	dp.ReportOK(check1)

	p.EXPECT().ReportOK(check1, health.StrAttr("k1", "v1")).Times(2)
	p.EXPECT().ReportOK(check1, health.StrAttr("k1", "v2")).Times(1)
	dp.ReportOK(check1, health.StrAttr("k1", "v1"))
	dp.ReportOK(check1, health.StrAttr("k1", "v2"))
	dp.ReportOK(check1, health.StrAttr("k1", "v1"))
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
