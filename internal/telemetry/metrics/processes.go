package metrics

import (
	"context"

	"github.com/prometheus/procfs"
	"go.opencensus.io/stats"
	"go.opencensus.io/stats/view"
)

// A ProcessCollector collects stats about a process.
type ProcessCollector struct {
	cpuTotal  *stats.Float64Measure
	openFDs   *stats.Int64Measure
	maxFDs    *stats.Int64Measure
	vsize     *stats.Int64Measure
	maxVsize  *stats.Int64Measure
	rss       *stats.Int64Measure
	startTime *stats.Float64Measure
	views     []*view.View
}

// NewProcessCollector creates a new ProcessCollector.
func NewProcessCollector(name string) *ProcessCollector {
	pc := &ProcessCollector{
		cpuTotal: stats.Float64(
			name+"_process_cpu_seconds_total",
			"Total user and system CPU time spent in seconds.",
			stats.UnitSeconds,
		),
		openFDs: stats.Int64(
			name+"_process_open_fds",
			"Number of open file descriptors.",
			"{file_descriptor}",
		),
		maxFDs: stats.Int64(
			name+"_process_max_fds",
			"Maximum number of open file descriptors.",
			"{file_descriptor}",
		),
		vsize: stats.Int64(
			name+"_process_virtual_memory_bytes",
			"Virtual memory size in bytes.",
			stats.UnitBytes,
		),
		maxVsize: stats.Int64(
			name+"_process_virtual_memory_max_bytes",
			"Maximum amount of virtual memory available in bytes.",
			stats.UnitBytes,
		),
		rss: stats.Int64(
			name+"_process_resident_memory_bytes",
			"Resident memory size in bytes.",
			stats.UnitBytes,
		),
		startTime: stats.Float64(
			name+"_process_start_time_seconds",
			"Start time of the process since unix epoch in seconds.",
			stats.UnitSeconds,
		),
	}
	pc.views = []*view.View{
		{
			Name:        pc.cpuTotal.Name(),
			Description: pc.cpuTotal.Description(),
			Measure:     pc.cpuTotal,
			Aggregation: view.Sum(),
		},
		{
			Name:        pc.openFDs.Name(),
			Description: pc.openFDs.Description(),
			Measure:     pc.openFDs,
			Aggregation: view.LastValue(),
		},
		{
			Name:        pc.maxFDs.Name(),
			Description: pc.maxFDs.Description(),
			Measure:     pc.maxFDs,
			Aggregation: view.LastValue(),
		},
		{
			Name:        pc.vsize.Name(),
			Description: pc.vsize.Description(),
			Measure:     pc.vsize,
			Aggregation: view.LastValue(),
		},
		{
			Name:        pc.maxVsize.Name(),
			Description: pc.maxVsize.Description(),
			Measure:     pc.maxVsize,
			Aggregation: view.LastValue(),
		},
		{
			Name:        pc.rss.Name(),
			Description: pc.rss.Description(),
			Measure:     pc.rss,
			Aggregation: view.LastValue(),
		},
		{
			Name:        pc.startTime.Name(),
			Description: pc.startTime.Description(),
			Measure:     pc.startTime,
			Aggregation: view.LastValue(),
		},
	}
	return pc
}

// Views returns the views for the process collector.
func (pc *ProcessCollector) Views() []*view.View {
	return pc.views
}

// Measure measures the stats for a process.
func (pc *ProcessCollector) Measure(ctx context.Context, pid int) error {
	proc, err := procfs.NewProc(pid)
	if err != nil {
		return err
	}

	procStat, err := proc.Stat()
	if err != nil {
		return err
	}

	procStartTime, err := procStat.StartTime()
	if err != nil {
		return err
	}

	procFDLen, err := proc.FileDescriptorsLen()
	if err != nil {
		return err
	}

	procLimits, err := proc.Limits()
	if err != nil {
		return err
	}

	stats.Record(ctx,
		pc.cpuTotal.M(procStat.CPUTime()),
		pc.openFDs.M(int64(procFDLen)),
		pc.maxFDs.M(procLimits.OpenFiles),
		pc.vsize.M(int64(procStat.VSize)),
		pc.maxVsize.M(procLimits.AddressSpace),
		pc.rss.M(int64(procStat.RSS)),
		pc.startTime.M(procStartTime),
	)
	return nil
}
