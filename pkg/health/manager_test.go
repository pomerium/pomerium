package health_test

import (
	"errors"
	"fmt"
	"maps"
	"runtime"
	"slices"
	"strings"
	"testing"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"

	"github.com/pomerium/pomerium/internal/log"
	health "github.com/pomerium/pomerium/pkg/health"
	"github.com/pomerium/pomerium/pkg/iterutil"
)

func recordedStatus(tr health.Tracker) []health.Status {
	recs := tr.GetRecords()
	return slices.Collect(iterutil.Convert(maps.Values(recs), func(r *health.Record) health.Status {
		return r.Status()
	}))
}

func recordedErrors(tr health.Tracker) []error {
	recs := tr.GetRecords()
	return slices.Collect(iterutil.Convert(maps.Values(recs), func(r *health.Record) error {
		return r.Err()
	}))
}

func TestManagerReplay(t *testing.T) {
	t.Parallel()
	assert := assert.New(t)
	mgr := health.NewManager()
	ctrl := gomock.NewController(t)
	id1, id2, id3 := health.ProviderID("id1"), health.ProviderID("id2"), health.ProviderID("id3")
	p1 := NewMockProvider(ctrl)
	p2 := NewMockProvider(ctrl)
	p3 := NewMockProvider(ctrl)
	mgr.Register(id1, p1)
	mgr.Register(id2, p2)

	check1 := health.Check("check-1")

	p1.EXPECT().ReportStatus(check1, health.StatusRunning).Times(1)
	p2.EXPECT().ReportStatus(check1, health.StatusRunning).Times(1)

	mgr.ReportStatus(check1, health.StatusRunning)

	assert.ElementsMatch(recordedStatus(mgr), []health.Status{health.StatusRunning})

	p3.EXPECT().ReportStatus(check1, health.StatusRunning).Times(1)
	mgr.Register(id3, p3)

	mgr.Deregister(id2)
	p1.EXPECT().ReportStatus(check1, health.StatusTerminating).Times(1)
	p3.EXPECT().ReportStatus(check1, health.StatusTerminating).Times(1)
	p2.EXPECT().ReportStatus(check1, health.StatusTerminating).Times(0)

	mgr.ReportStatus(check1, health.StatusTerminating)
	assert.ElementsMatch(recordedStatus(mgr), []health.Status{health.StatusTerminating})
}

func TestManagerDeduplication(t *testing.T) {
	t.Parallel()
	assert := assert.New(t)
	mgr := health.NewManager()

	ctrl := gomock.NewController(t)
	p1 := NewMockProvider(ctrl)
	p2 := NewMockProvider(ctrl)

	kv1, kv2 := health.StrAttr("k1", "v1"), health.StrAttr("k1", "v2")

	id1, id2 := health.ProviderID("id1"), health.ProviderID("id2")
	check1 := health.Check("check1")

	mgr.Register(id1, p1)

	p1.EXPECT().ReportStatus(check1, health.StatusRunning).Times(2)
	mgr.ReportStatus(check1, health.StatusRunning)
	mgr.ReportStatus(check1, health.StatusRunning)
	p2.EXPECT().ReportStatus(check1, health.StatusRunning).Times(2)
	mgr.Register(id2, p2)

	p1.EXPECT().ReportStatus(check1, health.StatusRunning, kv1).Times(2)
	p2.EXPECT().ReportStatus(check1, health.StatusRunning, kv1).Times(2)
	p1.EXPECT().ReportStatus(check1, health.StatusRunning, kv2).Times(1)
	p2.EXPECT().ReportStatus(check1, health.StatusRunning, kv2).Times(1)

	mgr.ReportStatus(check1, health.StatusRunning, kv1)
	mgr.ReportStatus(check1, health.StatusRunning, kv2)
	mgr.ReportStatus(check1, health.StatusRunning, kv1)

	err1, err2 := errors.New("error1"), errors.New("error2")

	p1.EXPECT().ReportError(check1, err1).Times(2)
	p2.EXPECT().ReportError(check1, err1).Times(2)
	p1.EXPECT().ReportError(check1, err2).Times(1)
	p2.EXPECT().ReportError(check1, err2).Times(1)

	mgr.ReportError(check1, err1)
	mgr.ReportError(check1, err1)
	assert.ElementsMatch(recordedErrors(mgr), []error{err1})
	mgr.ReportError(check1, err2)
	assert.ElementsMatch(recordedErrors(mgr), []error{err2})
	mgr.ReportError(check1, err1)
	assert.ElementsMatch(recordedStatus(mgr), []health.Status{health.StatusRunning})
	assert.ElementsMatch(recordedErrors(mgr), []error{err1})

	mgr.ReportStatus(check1, health.StatusRunning)

	assert.ElementsMatch(recordedErrors(mgr), []error{nil})
}

func TestDefaultManager(t *testing.T) {
	t.Parallel()
	ctrl := gomock.NewController(t)

	p1 := NewMockProvider(ctrl)
	p2 := NewMockProvider(ctrl)
	id1, id2 := health.ProviderID("id1"), health.ProviderID("id2")
	check1 := health.Check("check1")

	mgr := health.GetProviderManager()
	mgr.Register(id1, p1)
	mgr.Register(id2, p2)

	p1.EXPECT().ReportStatus(check1, health.StatusRunning).Times(1)
	p2.EXPECT().ReportStatus(check1, health.StatusRunning).Times(1)

	mgr.ReportStatus(check1, health.StatusRunning)
}

func BenchmarkManagerMem(b *testing.B) {
	prevLevel := log.GetLevel()
	log.SetLevel(zerolog.InfoLevel)
	defer log.SetLevel(prevLevel)
	mgr := health.NewManager()
	start := &runtime.MemStats{}
	end := &runtime.MemStats{}

	runtime.ReadMemStats(start)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		mgr.ReportStatus(health.Check(fmt.Sprintf("%d", i)), health.StatusRunning)
	}
	b.StopTimer()
	runtime.ReadMemStats(end)
	logMemStats(b, start, end)
}

func logMemStats(b *testing.B, start, end *runtime.MemStats) {
	b.Logf("| %d | Alloc : %d\n", b.N, end.Alloc-start.Alloc)
	b.Logf("| %d | Mallocs : %d\n", b.N, end.Mallocs-start.Mallocs)
}

func BenchmarkManagerLargeError(b *testing.B) {
	prevLevel := log.GetLevel()
	log.SetLevel(zerolog.InfoLevel)
	defer log.SetLevel(prevLevel)
	mgr := health.NewManager()
	start := &runtime.MemStats{}
	end := &runtime.MemStats{}
	sb := strings.Builder{}
	for i := 0; i < 100; i++ {
		sb.WriteString("asdqwekl")
	}
	largeErr := errors.New(sb.String())

	runtime.ReadMemStats(start)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		mgr.ReportStatus(health.Check(fmt.Sprintf("%d", i)), health.StatusRunning)
	}

	for i := 0; i < b.N; i++ {
		mgr.ReportError(health.Check(fmt.Sprintf("%d", i)), largeErr)
	}
	b.StopTimer()
	runtime.ReadMemStats(end)
	logMemStats(b, start, end)
}

func BenchmarkDeduplicateError(b *testing.B) {
	prevLevel := log.GetLevel()
	log.SetLevel(zerolog.InfoLevel)
	defer log.SetLevel(prevLevel)
	mgr := health.NewManager()
	start := &runtime.MemStats{}
	end := &runtime.MemStats{}
	sb := strings.Builder{}
	for i := 0; i < 100; i++ {
		sb.WriteString("asdqwekl")
	}
	largeErr := errors.New(sb.String())

	runtime.ReadMemStats(start)
	b.ResetTimer()
	for i := 0; i < 5; i++ {
		for i := 0; i < b.N; i++ {
			mgr.ReportError(health.Check(fmt.Sprintf("%d", i)), largeErr)
		}
	}
	b.StopTimer()
	runtime.ReadMemStats(end)
	logMemStats(b, start, end)
}
