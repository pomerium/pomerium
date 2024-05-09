package envoy

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	envoy_config_bootstrap_v3 "github.com/envoyproxy/go-control-plane/envoy/config/bootstrap/v3"
	envoy_config_overload_v3 "github.com/envoyproxy/go-control-plane/envoy/config/overload/v3"
	envoy_extensions_resource_monitors_injected_resource_v3 "github.com/envoyproxy/go-control-plane/envoy/extensions/resource_monitors/injected_resource/v3"
	typev3 "github.com/envoyproxy/go-control-plane/envoy/type/v3"
	atomicfs "github.com/natefinch/atomic"
	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/internal/telemetry/metrics"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
)

type ResourceMonitor interface {
	Run(ctx context.Context, envoyPid int) error
	ApplyBootstrapConfig(bootstrap *envoy_config_bootstrap_v3.Bootstrap)
}

type CgroupFilePath int

const (
	RootPath CgroupFilePath = iota
	MemoryUsagePath
	MemoryLimitPath
)

type CgroupDriver interface {
	CgroupForPid(pid int) (string, error)
	Path(cgroup string, kind CgroupFilePath) string
	Validate(cgroup string) error
	MemoryUsage(cgroup string) (uint64, error)
	MemoryLimit(cgroup string) (uint64, error)
}

var (
	overloadActions = []struct {
		Name    string
		Trigger *envoy_config_overload_v3.Trigger
	}{
		{"shrink_heap", memUsageScaled(0.8, 0.9)},
		{"reduce_timeouts", memUsageScaled(0.85, 0.95)},
		{"reset_high_memory_stream", memUsageScaled(0.90, 0.95)},
		{"stop_accepting_connections", memUsageThreshold(0.95)},
		{"disable_http_keepalive", memUsageThreshold(0.97)},
		{"stop_accepting_requests", memUsageThreshold(0.99)},
	}
	overloadActionConfigs = map[string]*anypb.Any{
		"reduce_timeouts": marshalAny(&envoy_config_overload_v3.ScaleTimersOverloadActionConfig{
			TimerScaleFactors: []*envoy_config_overload_v3.ScaleTimersOverloadActionConfig_ScaleTimer{
				{
					Timer: envoy_config_overload_v3.ScaleTimersOverloadActionConfig_HTTP_DOWNSTREAM_CONNECTION_IDLE,
					OverloadAdjust: &envoy_config_overload_v3.ScaleTimersOverloadActionConfig_ScaleTimer_MinScale{
						MinScale: &typev3.Percent{
							Value: 50, // reduce the idle timeout by 50%
						},
					},
				},
			},
		}),
	}
	recordActionThresholdsOnce sync.Once
	computedActionThresholds   = make(map[string]float64)
)

func init() {
	for _, action := range overloadActions {
		var minThreshold float64
		switch trigger := action.Trigger.TriggerOneof.(type) {
		case *envoy_config_overload_v3.Trigger_Scaled:
			minThreshold = trigger.Scaled.ScalingThreshold
		case *envoy_config_overload_v3.Trigger_Threshold:
			minThreshold = trigger.Threshold.Value
		}
		computedActionThresholds[action.Name] = minThreshold
	}
}

func recordActionThresholds() {
	recordActionThresholdsOnce.Do(func() {
		for name, minThreshold := range computedActionThresholds {
			metrics.RecordEnvoyOverloadActionThreshold(context.Background(), name, minThreshold)
		}
	})
}

const (
	groupMemory = "memory"

	metricCgroupMemorySaturation = "cgroup_memory_saturation"
)

// NewSharedResourceMonitor creates a new ResourceMonitor suitable for running
// envoy in the same cgroup as the parent process. It reports the cgroup's
// memory saturation to envoy as an injected resource. This allows envoy to
// react to actual memory pressure in the cgroup, taking into account memory
// usage from pomerium itself.
func NewSharedResourceMonitor(tempDir string) (ResourceMonitor, error) {
	driver, err := SystemCgroupDriver()
	if err != nil {
		return nil, err
	}
	recordActionThresholds()

	selfCgroup, err := driver.CgroupForPid(os.Getpid())
	if err != nil {
		return nil, fmt.Errorf("failed to look up cgroup: %w", err)
	}
	if err := driver.Validate(selfCgroup); err != nil {
		return nil, fmt.Errorf("cgroup not valid for resource monitoring: %w", err)
	}

	if err := os.MkdirAll(filepath.Join(tempDir, "resource_monitor", groupMemory), 0o755); err != nil {
		return nil, fmt.Errorf("failed to create resource monitor directory: %w", err)
	}

	s := &sharedResourceMonitor{
		driver:  driver,
		cgroup:  selfCgroup,
		tempDir: filepath.Join(tempDir, "resource_monitor"),
	}

	if err := s.writeMetricFile(groupMemory, metricCgroupMemorySaturation, "0", 0o644); err != nil {
		return nil, fmt.Errorf("failed to initialize metrics: %w", err)
	}
	return s, nil
}

type sharedResourceMonitor struct {
	driver  CgroupDriver
	cgroup  string
	tempDir string
}

func (s *sharedResourceMonitor) metricFilename(group, name string) string {
	return filepath.Join(s.tempDir, group, name)
}

func memUsageScaled(scaling, saturation float64) *envoy_config_overload_v3.Trigger {
	return &envoy_config_overload_v3.Trigger{
		Name: "envoy.resource_monitors.injected_resource",
		TriggerOneof: &envoy_config_overload_v3.Trigger_Scaled{
			Scaled: &envoy_config_overload_v3.ScaledTrigger{
				ScalingThreshold:    scaling,
				SaturationThreshold: saturation,
			},
		},
	}
}

func memUsageThreshold(threshold float64) *envoy_config_overload_v3.Trigger {
	return &envoy_config_overload_v3.Trigger{
		Name: "envoy.resource_monitors.injected_resource",
		TriggerOneof: &envoy_config_overload_v3.Trigger_Threshold{
			Threshold: &envoy_config_overload_v3.ThresholdTrigger{
				Value: threshold,
			},
		},
	}
}

func (s *sharedResourceMonitor) ApplyBootstrapConfig(bootstrap *envoy_config_bootstrap_v3.Bootstrap) {
	if bootstrap.OverloadManager == nil {
		bootstrap.OverloadManager = &envoy_config_overload_v3.OverloadManager{}
	}

	bootstrap.OverloadManager.ResourceMonitors = append(bootstrap.OverloadManager.ResourceMonitors,
		&envoy_config_overload_v3.ResourceMonitor{
			Name: "envoy.resource_monitors.injected_resource",
			ConfigType: &envoy_config_overload_v3.ResourceMonitor_TypedConfig{
				TypedConfig: marshalAny(&envoy_extensions_resource_monitors_injected_resource_v3.InjectedResourceConfig{
					Filename: s.metricFilename(groupMemory, metricCgroupMemorySaturation),
				}),
			},
		},
	)

	for _, action := range overloadActions {
		bootstrap.OverloadManager.Actions = append(bootstrap.OverloadManager.Actions,
			&envoy_config_overload_v3.OverloadAction{
				Name:        fmt.Sprintf("envoy.overload_actions.%s", action.Name),
				Triggers:    []*envoy_config_overload_v3.Trigger{action.Trigger},
				TypedConfig: overloadActionConfigs[action.Name],
			},
		)
	}

	bootstrap.OverloadManager.BufferFactoryConfig = &envoy_config_overload_v3.BufferFactoryConfig{
		MinimumAccountToTrackPowerOfTwo: 20,
	}
}

func (s *sharedResourceMonitor) Run(ctx context.Context, envoyPid int) error {
	envoyCgroup, err := s.driver.CgroupForPid(envoyPid)
	if err != nil {
		return fmt.Errorf("failed to look up cgroup for envoy process: %w", err)
	}
	if envoyCgroup != s.cgroup {
		return fmt.Errorf("envoy process is not in the expected cgroup: %s", envoyCgroup)
	}
	log.Info(ctx).Str("service", "envoy").Str("cgroup", s.cgroup).Msg("starting resource monitor")

	limitWatcher := &memoryLimitWatcher{
		limitFilePath: s.driver.Path(s.cgroup, MemoryLimitPath),
	}
	if err := limitWatcher.Watch(ctx); err != nil {
		return fmt.Errorf("failed to start watch on cgroup memory limit: %w", err)
	}

	// Set initial values for state metrics
	s.updateActionStates(ctx, 0)

	// The interval at which we check memory usage is scaled based on the current
	// memory saturation. When memory usage is low, we check less frequently, and
	// as the saturation increases, we also increase the frequency of checks. Most
	// of the thresholds at which some action is taken to reduce memory usage are
	// very high (e.g. 95% of the limit). As memory usage approaches this limit,
	// it becomes increasingly important to have accurate data, since memory usage
	// can change rapidly; we want to avoid hitting the limit, but also delay
	// taking disruptive actions for as long as possible.

	// the envoy default interval for the builtin heap monitor is 1s
	initialTickDuration := 1 * time.Second
	maxTickDuration := 5 * time.Second
	minTickDuration := 250 * time.Millisecond
	tick := time.NewTimer(initialTickDuration)
	var lastValue string
	for {
		select {
		case <-ctx.Done():
			tick.Stop()
			return ctx.Err()
		case <-tick.C:
			usage, err := s.driver.MemoryUsage(s.cgroup)
			if err != nil {
				log.Error(ctx).Err(err).Msg("failed to get memory saturation")
				continue
			}
			var saturation float64
			if limit := limitWatcher.Value(); limit > 0 {
				saturation = float64(usage) / float64(limit)
			}

			saturationStr := fmt.Sprintf("%.6f", saturation)
			nextInterval := (maxTickDuration - (time.Duration(float64(maxTickDuration-minTickDuration) * saturation))).
				Round(time.Millisecond)

			if saturationStr != lastValue {
				lastValue = saturationStr
				s.writeMetricFile(groupMemory, metricCgroupMemorySaturation, saturationStr, 0o644)
				s.updateActionStates(ctx, saturation)
				metrics.RecordEnvoyCgroupMemorySaturation(ctx, s.cgroup, saturation)
				log.Debug(ctx).
					Str("service", "envoy").
					Str("metric", metricCgroupMemorySaturation).
					Str("value", saturationStr).
					Dur("interval_ms", nextInterval).
					Msg("updated metric")
			}

			tick.Reset(nextInterval)
		}
	}
}

func (s *sharedResourceMonitor) updateActionStates(ctx context.Context, pct float64) {
	for name, minThreshold := range computedActionThresholds {
		var state int64
		if pct >= minThreshold {
			state = 1
		}
		metrics.RecordEnvoyOverloadActionState(ctx,
			metrics.EnvoyOverloadActionStateTags{
				Cgroup:     s.cgroup,
				ActionName: name,
			},
			state,
		)
	}
}

func (s *sharedResourceMonitor) writeMetricFile(group, name, data string, mode fs.FileMode) error {
	// Logic here is similar to atomic.WriteFile, but because envoy watches the
	// parent directory for changes to any file, we write the temp file one level
	// up before moving it into the watched location, to avoid triggering inotify
	// events for the temp file.
	f, err := os.CreateTemp(s.tempDir, name)
	if err != nil {
		return err
	}
	tempFilename := f.Name()
	defer os.Remove(tempFilename)
	defer f.Close()
	if _, err := f.Write([]byte(data)); err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tempFilename, mode); err != nil {
		return err
	}
	if err := atomicfs.ReplaceFile(tempFilename, filepath.Join(s.tempDir, group, name)); err != nil {
		return err
	}
	return nil
}

type cgroupV2Driver struct {
	root string
}

func (d *cgroupV2Driver) Path(cgroup string, kind CgroupFilePath) string {
	switch kind {
	case RootPath:
		return d.root
	case MemoryUsagePath:
		return filepath.Join(d.root, cgroup, "memory.current")
	case MemoryLimitPath:
		return filepath.Join(d.root, cgroup, "memory.max")
	}
	return ""
}

func (*cgroupV2Driver) CgroupForPid(pid int) (string, error) {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/cgroup", pid))
	if err != nil {
		return "", err
	}
	return parseCgroupName(data)
}

// MemoryUsage implements CgroupDriver.
func (d *cgroupV2Driver) MemoryUsage(cgroup string) (uint64, error) {
	current, err := os.ReadFile(d.Path(cgroup, MemoryUsagePath))
	if err != nil {
		return 0, err
	}
	return strconv.ParseUint(strings.TrimSpace(string(current)), 10, 64)
}

// MemoryLimit implements CgroupDriver.
func (d *cgroupV2Driver) MemoryLimit(cgroup string) (uint64, error) {
	max, err := os.ReadFile(d.Path(cgroup, MemoryLimitPath))
	if err != nil {
		return 0, err
	}
	if string(max) == "max" {
		return 0, nil
	}
	return strconv.ParseUint(strings.TrimSpace(string(max)), 10, 64)
}

// Validate implements CgroupDriver.
func (d *cgroupV2Driver) Validate(cgroup string) error {
	if typ, err := os.ReadFile(filepath.Join(d.root, cgroup, "cgroup.type")); err != nil {
		return err
	} else if strings.TrimSpace(string(typ)) != "domain" {
		return errors.New("not a domain cgroup")
	}

	if controllers, err := d.enabledSubtreeControllers(cgroup); err != nil {
		return err
	} else if len(controllers) > 0 {
		return errors.New("not a leaf cgroup")
	}

	if controllers, err := d.enabledControllers(cgroup); err != nil {
		return err
	} else if !slices.Contains(controllers, "memory") {
		return errors.New("memory controller not enabled")
	}

	return nil
}

func (d *cgroupV2Driver) enabledControllers(cgroup string) ([]string, error) {
	data, err := os.ReadFile(filepath.Join(d.root, cgroup, "cgroup.controllers"))
	if err != nil {
		return nil, err
	}
	return strings.Fields(string(data)), nil
}

func (d *cgroupV2Driver) enabledSubtreeControllers(cgroup string) ([]string, error) {
	data, err := os.ReadFile(filepath.Join(d.root, cgroup, "cgroup.subtree_control"))
	if err != nil {
		return nil, err
	}
	return strings.Fields(string(data)), nil
}

var _ CgroupDriver = (*cgroupV2Driver)(nil)

type cgroupV1Driver struct {
	root string
}

func (d *cgroupV1Driver) Path(cgroup string, kind CgroupFilePath) string {
	switch kind {
	case RootPath:
		return d.root
	case MemoryUsagePath:
		return filepath.Join(d.root, "memory", cgroup, "memory.usage_in_bytes")
	case MemoryLimitPath:
		return filepath.Join(d.root, "memory", cgroup, "memory.limit_in_bytes")
	}
	return ""
}

func (d *cgroupV1Driver) CgroupForPid(pid int) (string, error) {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/cgroup", pid))
	if err != nil {
		return "", err
	}
	name, err := parseCgroupName(data)
	if err != nil {
		return "", err
	}

	mountinfo, err := os.ReadFile(fmt.Sprintf("/proc/%d/mountinfo", pid))
	if err != nil {
		return "", err
	}
	scanner := bufio.NewScanner(bytes.NewReader(mountinfo))
	for scanner.Scan() {
		line := strings.Fields(scanner.Text())
		if len(line) < 5 {
			continue
		}
		// entries 3 and 4 contain the cgroup path and the mountpoint, respectively.
		// each resource will contain a separate mountpoint for the same path, so
		// we can just pick the first one.
		if line[3] == name {
			mountpoint, err := filepath.Rel(d.root, filepath.Dir(line[4]))
			if err != nil {
				return "", err
			}
			return filepath.Clean("/" + mountpoint), nil
		}
	}
	return "", errors.New("cgroup not found")
}

// MemoryUsage implements CgroupDriver.
func (d *cgroupV1Driver) MemoryUsage(cgroup string) (uint64, error) {
	current, err := os.ReadFile(d.Path(cgroup, MemoryUsagePath))
	if err != nil {
		return 0, err
	}
	return strconv.ParseUint(strings.TrimSpace(string(current)), 10, 64)
}

// MemoryLimit implements CgroupDriver.
func (d *cgroupV1Driver) MemoryLimit(cgroup string) (uint64, error) {
	max, err := os.ReadFile(d.Path(cgroup, MemoryLimitPath))
	if err != nil {
		return 0, err
	}
	if string(max) == "max" {
		return 0, nil
	}
	return strconv.ParseUint(strings.TrimSpace(string(max)), 10, 64)
}

// Validate implements CgroupDriver.
func (d *cgroupV1Driver) Validate(cgroup string) error {
	memoryPath := filepath.Join(d.root, "memory", cgroup)
	info, err := os.Stat(memoryPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return errors.New("memory controller not enabled")
		}
		return fmt.Errorf("failed to stat cgroup: %w", err)
	}
	if !info.IsDir() {
		return fmt.Errorf("%s is not a directory", memoryPath)
	}
	return nil
}

var _ CgroupDriver = (*cgroupV1Driver)(nil)

func SystemCgroupDriver() (CgroupDriver, error) {
	const cgv2Magic = 0x63677270

	fsType := func(path string) (int64, error) {
		for {
			var stat syscall.Statfs_t
			err := syscall.Statfs(path, &stat)
			if err != nil {
				if errors.Is(err, syscall.EINTR) {
					continue
				}
				return 0, err
			}
			return stat.Type, nil
		}
	}

	// fast path: cgroup2 only
	t, err := fsType("/sys/fs/cgroup")
	if err != nil {
		return nil, err
	}
	if t == cgv2Magic {
		return &cgroupV2Driver{root: "/sys/fs/cgroup"}, nil
	}

	// find the unified mountpoint, or fall back to v1
	mounts, err := os.ReadFile("/proc/self/mounts")
	if err != nil {
		return nil, err
	}
	scanner := bufio.NewScanner(bytes.NewReader(mounts))
	var cgv1Root string
	for scanner.Scan() {
		line := strings.Fields(scanner.Text())
		if len(line) < 3 {
			continue
		}
		switch line[2] {
		case "cgroup2":
			return &cgroupV2Driver{root: line[1]}, nil
		case "cgroup":
			if cgv1Root == "" {
				cgv1Root = filepath.Dir(line[1])
			}
		}
	}

	if cgv1Root != "" {
		return &cgroupV1Driver{root: cgv1Root}, nil
	}

	return nil, errors.New("no cgroup mount found")
}

func parseCgroupName(contents []byte) (string, error) {
	scan := bufio.NewScanner(bytes.NewReader(contents))
	for scan.Scan() {
		line := scan.Text()
		if strings.HasPrefix(line, "0::") {
			return strings.Split(strings.TrimPrefix(strings.TrimSpace(string(line)), "0::"), " ")[0], nil
		}
	}
	return "", errors.New("cgroup not found")
}

func marshalAny(msg proto.Message) *anypb.Any {
	data := new(anypb.Any)
	_ = anypb.MarshalFrom(data, msg, proto.MarshalOptions{
		AllowPartial:  true,
		Deterministic: true,
	})
	return data
}

type memoryLimitWatcher struct {
	limitFilePath string

	value atomic.Int64
}

func (w *memoryLimitWatcher) Value() int64 {
	return w.value.Load()
}

func (w *memoryLimitWatcher) readValue() (int64, error) {
	data, err := os.ReadFile(w.limitFilePath)
	if err != nil {
		return 0, err
	}
	if string(data) == "max" {
		// no limit set
		return 0, nil
	}
	return strconv.ParseInt(strings.TrimSpace(string(data)), 10, 64)
}

func (w *memoryLimitWatcher) Watch(ctx context.Context) error {
	fd, err := syscall.InotifyInit1(syscall.IN_CLOEXEC)
	if err != nil {
		return err
	}
	closeWatch := sync.OnceFunc(func() {
		log.Debug(ctx).Msg("stopping memory limit watcher")
		for {
			if err := syscall.Close(fd); !errors.Is(err, syscall.EINTR) {
				return
			}
		}
	})
	if _, err := syscall.InotifyAddWatch(fd, w.limitFilePath, syscall.IN_MODIFY); err != nil {
		closeWatch()
		return err
	}

	// perform the initial read synchronously and only after setting up the watch
	v, err := w.readValue()
	if err != nil {
		closeWatch()
		return err
	}
	w.value.Store(v)
	log.Debug(ctx).Int64("bytes", v).Msg("current memory limit")

	context.AfterFunc(ctx, closeWatch) // to unblock syscall.Read below
	go func() {
		defer closeWatch()
		var buf [syscall.SizeofInotifyEvent]byte
		for {
			v, err := w.readValue()
			if err != nil {
				return
			}
			if prev := w.value.Swap(v); prev != v {
				log.Debug(ctx).
					Int64("prev", prev).
					Int64("current", v).
					Msg("memory limit updated")
			}
			_, err = syscall.Read(fd, buf[:])
			if err != nil {
				if errors.Is(err, syscall.EINTR) {
					continue
				}
				return
			}
		}
	}()

	return nil
}
