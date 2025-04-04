//go:build linux

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
	"time"
	"unsafe"

	envoy_config_bootstrap_v3 "github.com/envoyproxy/go-control-plane/envoy/config/bootstrap/v3"
	envoy_config_overload_v3 "github.com/envoyproxy/go-control-plane/envoy/config/overload/v3"
	envoy_extensions_resource_monitors_injected_resource_v3 "github.com/envoyproxy/go-control-plane/envoy/extensions/resource_monitors/injected_resource/v3"
	typev3 "github.com/envoyproxy/go-control-plane/envoy/type/v3"
	atomicfs "github.com/natefinch/atomic"
	"golang.org/x/sys/unix"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/internal/telemetry/metrics"
)

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
		ActionName string
		Trigger    *envoy_config_overload_v3.Trigger
	}{
		// At 90%, envoy will shrink its heap every 10 seconds
		// https://github.com/envoyproxy/envoy/blob/v1.30.1/source/common/memory/heap_shrinker.cc
		{"shrink_heap", memUsageThreshold(0.9)},

		// At >85% memory usage, gradually start reducing timeouts, by up to 50%.
		// https://www.envoyproxy.io/docs/envoy/latest/configuration/operations/overload_manager/overload_manager#reducing-timeouts
		// https://github.com/envoyproxy/envoy/blob/v1.30.1/source/server/overload_manager_impl.cc#L565-L572
		{"reduce_timeouts", memUsageScaled(0.85, 0.95)},

		// At 90%, start resetting streams using the most memory. As memory usage
		// increases, the eligibility threshold is reduced.
		// https://www.envoyproxy.io/docs/envoy/latest/configuration/operations/overload_manager/overload_manager#reset-streams
		// https://github.com/envoyproxy/envoy/blob/v1.30.1/source/server/worker_impl.cc#L180
		{"reset_high_memory_stream", memUsageScaled(0.90, 0.98)},

		// At 95%, stop accepting new connections, but keep existing ones open.
		// https://github.com/envoyproxy/envoy/blob/v1.30.1/source/server/worker_impl.cc#L168-L174
		{"stop_accepting_connections", memUsageThreshold(0.95)},

		// At 98%, disable HTTP keepalive. This prevents new http/2 streams and
		// ends all existing ones.
		// https://github.com/envoyproxy/envoy/blob/v1.30.1/source/common/http/conn_manager_impl.cc#L1735-L1755
		{"disable_http_keepalive", memUsageThreshold(0.98)},

		// At 99%, drop all new requests.
		// https://github.com/envoyproxy/envoy/blob/v1.30.1/source/common/http/conn_manager_impl.cc#L1203-L1225
		{"stop_accepting_requests", memUsageThreshold(0.99)},
	}
	overloadActionConfigs = map[string]*anypb.Any{
		"reduce_timeouts": marshalAny(&envoy_config_overload_v3.ScaleTimersOverloadActionConfig{
			TimerScaleFactors: []*envoy_config_overload_v3.ScaleTimersOverloadActionConfig_ScaleTimer{
				{
					Timer: envoy_config_overload_v3.ScaleTimersOverloadActionConfig_HTTP_DOWNSTREAM_CONNECTION_IDLE,
					OverloadAdjust: &envoy_config_overload_v3.ScaleTimersOverloadActionConfig_ScaleTimer_MinScale{
						MinScale: &typev3.Percent{
							Value: 50, // reduce the idle timeout by 50% at most
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
		computedActionThresholds[action.ActionName] = minThreshold
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

type ResourceMonitorOptions struct {
	driver CgroupDriver
}

type ResourceMonitorOption func(*ResourceMonitorOptions)

func (o *ResourceMonitorOptions) apply(opts ...ResourceMonitorOption) {
	for _, op := range opts {
		op(o)
	}
}

// WithCgroupDriver overrides the cgroup driver used for the resource monitor.
// If unset, it will be chosen automatically.
func WithCgroupDriver(driver CgroupDriver) ResourceMonitorOption {
	return func(o *ResourceMonitorOptions) {
		o.driver = driver
	}
}

// NewSharedResourceMonitor creates a new ResourceMonitor suitable for running
// envoy in the same cgroup as the parent process. It reports the cgroup's
// memory saturation to envoy as an injected resource. This allows envoy to
// react to actual memory pressure in the cgroup, taking into account memory
// usage from pomerium itself.
func NewSharedResourceMonitor(ctx context.Context, src config.Source, tempDir string, opts ...ResourceMonitorOption) (ResourceMonitor, error) {
	options := ResourceMonitorOptions{}
	options.apply(opts...)
	if options.driver == nil {
		var err error
		options.driver, err = DetectCgroupDriver()
		if err != nil {
			return nil, err
		}
	}
	recordActionThresholds()

	selfCgroup, err := options.driver.CgroupForPid(os.Getpid())
	if err != nil {
		return nil, fmt.Errorf("failed to look up cgroup: %w", err)
	}
	if err := options.driver.Validate(selfCgroup); err != nil {
		return nil, fmt.Errorf("cgroup not valid for resource monitoring: %w", err)
	}

	if err := os.MkdirAll(filepath.Join(tempDir, "resource_monitor", groupMemory), 0o755); err != nil {
		return nil, fmt.Errorf("failed to create resource monitor directory: %w", err)
	}

	s := &sharedResourceMonitor{
		ResourceMonitorOptions: options,
		cgroup:                 selfCgroup,
		tempDir:                filepath.Join(tempDir, "resource_monitor"),
	}
	readInitialConfig := make(chan struct{})
	src.OnConfigChange(ctx, func(ctx context.Context, c *config.Config) {
		<-readInitialConfig
		s.onConfigChange(ctx, c)
	})
	s.onConfigChange(ctx, src.GetConfig())
	close(readInitialConfig)

	if err := s.writeMetricFile(groupMemory, metricCgroupMemorySaturation, "0", 0o644); err != nil {
		return nil, fmt.Errorf("failed to initialize metrics: %w", err)
	}
	return s, nil
}

type sharedResourceMonitor struct {
	ResourceMonitorOptions
	cgroup  string
	tempDir string
	enabled atomic.Bool
}

func (s *sharedResourceMonitor) onConfigChange(_ context.Context, cfg *config.Config) {
	if cfg == nil || cfg.Options == nil {
		s.enabled.Store(config.DefaultRuntimeFlags()[config.RuntimeFlagEnvoyResourceManager])
		return
	}
	s.enabled.Store(cfg.Options.IsRuntimeFlagSet(config.RuntimeFlagEnvoyResourceManager))
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
				Name:        fmt.Sprintf("envoy.overload_actions.%s", action.ActionName),
				Triggers:    []*envoy_config_overload_v3.Trigger{action.Trigger},
				TypedConfig: overloadActionConfigs[action.ActionName],
			},
		)
	}

	bootstrap.OverloadManager.BufferFactoryConfig = &envoy_config_overload_v3.BufferFactoryConfig{
		// https://www.envoyproxy.io/docs/envoy/latest/api-v3/config/overload/v3/overload.proto#config-overload-v3-bufferfactoryconfig
		MinimumAccountToTrackPowerOfTwo: 20,
	}
}

var (
	monitorInitialTickDelay = 1 * time.Second
	monitorMaxTickInterval  = 10 * time.Second
	monitorMinTickInterval  = 250 * time.Millisecond
)

func (s *sharedResourceMonitor) Run(ctx context.Context, envoyPid int) error {
	envoyCgroup, err := s.driver.CgroupForPid(envoyPid)
	if err != nil {
		return fmt.Errorf("failed to look up cgroup for envoy process: %w", err)
	}
	if envoyCgroup != s.cgroup {
		return fmt.Errorf("envoy process is not in the expected cgroup: %s", envoyCgroup)
	}
	log.Ctx(ctx).Info().Str("service", "envoy").Str("cgroup", s.cgroup).Msg("starting resource monitor")

	ctx, ca := context.WithCancelCause(ctx)

	limitWatcher := &memoryLimitWatcher{
		limitFilePath: filepath.Clean("/" + s.driver.Path(s.cgroup, MemoryLimitPath)),
	}

	watcherExited := make(chan struct{})
	if err := limitWatcher.Watch(ctx); err != nil {
		ca(nil)
		return fmt.Errorf("failed to start watch on cgroup memory limit: %w", err)
	}
	go func() {
		limitWatcher.Wait()
		ca(errors.New("memory limit watcher stopped"))
		close(watcherExited)
	}()

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

	tick := time.NewTimer(monitorInitialTickDelay)
	var lastValue string
LOOP:
	for {
		select {
		case <-ctx.Done():
			tick.Stop()
			break LOOP
		case <-tick.C:
			var saturation float64
			if s.enabled.Load() {
				if limit := limitWatcher.Value(); limit > 0 {
					usage, err := s.driver.MemoryUsage(s.cgroup)
					if err != nil {
						log.Ctx(ctx).Error().Err(err).Msg("failed to get memory saturation")
						continue
					}
					saturation = max(0.0, min(1.0, float64(usage)/float64(limit)))
				}
			}

			saturationStr := fmt.Sprintf("%.6f", saturation)
			nextInterval := computeScaledTickInterval(saturation)

			if saturationStr != lastValue {
				lastValue = saturationStr
				if err := s.writeMetricFile(groupMemory, metricCgroupMemorySaturation, saturationStr, 0o644); err != nil {
					log.Ctx(ctx).Error().Err(err).Msg("failed to write metric file")
				}
				s.updateActionStates(ctx, saturation)
				metrics.RecordEnvoyCgroupMemorySaturation(ctx, s.cgroup, saturation)
				log.Ctx(ctx).Debug().
					Str("service", "envoy").
					Str("metric", metricCgroupMemorySaturation).
					Str("value", saturationStr).
					Dur("interval_ms", nextInterval).
					Msg("updated metric")
			}

			tick.Reset(nextInterval)
		}
	}

	<-watcherExited
	return context.Cause(ctx)
}

// Returns a value between monitorMinTickInterval and monitorMaxTickInterval, based
// on the given saturation value in the range [0.0, 1.0].
func computeScaledTickInterval(saturation float64) time.Duration {
	return monitorMaxTickInterval - (time.Duration(float64(monitorMaxTickInterval-monitorMinTickInterval) * max(0.0, min(1.0, saturation)))).
		Round(time.Millisecond)
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
	fs   fs.FS
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

func (d *cgroupV2Driver) CgroupForPid(pid int) (string, error) {
	data, err := fs.ReadFile(d.fs, fmt.Sprintf("proc/%d/cgroup", pid))
	if err != nil {
		return "", err
	}
	return parseCgroupName(data)
}

// MemoryUsage implements CgroupDriver.
func (d *cgroupV2Driver) MemoryUsage(cgroup string) (uint64, error) {
	current, err := fs.ReadFile(d.fs, d.Path(cgroup, MemoryUsagePath))
	if err != nil {
		return 0, err
	}
	return strconv.ParseUint(strings.TrimSpace(string(current)), 10, 64)
}

// MemoryLimit implements CgroupDriver.
func (d *cgroupV2Driver) MemoryLimit(cgroup string) (uint64, error) {
	data, err := fs.ReadFile(d.fs, d.Path(cgroup, MemoryLimitPath))
	if err != nil {
		return 0, err
	}
	v := strings.TrimSpace(string(data))
	if v == "max" {
		return 0, nil
	}
	return strconv.ParseUint(v, 10, 64)
}

// Validate implements CgroupDriver.
func (d *cgroupV2Driver) Validate(cgroup string) error {
	if typ, err := fs.ReadFile(d.fs, filepath.Join(d.root, cgroup, "cgroup.type")); err != nil {
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
	data, err := fs.ReadFile(d.fs, filepath.Join(d.root, cgroup, "cgroup.controllers"))
	if err != nil {
		return nil, err
	}
	return strings.Fields(string(data)), nil
}

func (d *cgroupV2Driver) enabledSubtreeControllers(cgroup string) ([]string, error) {
	data, err := fs.ReadFile(d.fs, filepath.Join(d.root, cgroup, "cgroup.subtree_control"))
	if err != nil {
		return nil, err
	}
	return strings.Fields(string(data)), nil
}

var _ CgroupDriver = (*cgroupV2Driver)(nil)

type cgroupV1Driver struct {
	fs   fs.FS
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
	data, err := fs.ReadFile(d.fs, fmt.Sprintf("proc/%d/cgroup", pid))
	if err != nil {
		return "", err
	}
	name, err := parseCgroupName(data)
	if err != nil {
		return "", err
	}

	mountinfo, err := fs.ReadFile(d.fs, fmt.Sprintf("proc/%d/mountinfo", pid))
	if err != nil {
		return "", err
	}
	scanner := bufio.NewScanner(bytes.NewReader(mountinfo))
	for scanner.Scan() {
		line := strings.Fields(scanner.Text())
		if len(line) < 5 {
			continue
		}

		// Entries 3 and 4 contain the root path and the mountpoint, respectively.
		// each resource will contain a separate mountpoint for the same path, so
		// we can just pick one.
		if line[4] == fmt.Sprintf("/%s/memory", d.root) {
			mountpoint, err := filepath.Rel(line[3], name)
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
	current, err := fs.ReadFile(d.fs, d.Path(cgroup, MemoryUsagePath))
	if err != nil {
		return 0, err
	}
	return strconv.ParseUint(strings.TrimSpace(string(current)), 10, 64)
}

// MemoryLimit implements CgroupDriver.
func (d *cgroupV1Driver) MemoryLimit(cgroup string) (uint64, error) {
	data, err := fs.ReadFile(d.fs, d.Path(cgroup, MemoryLimitPath))
	if err != nil {
		return 0, err
	}
	v := strings.TrimSpace(string(data))
	if v == "max" {
		return 0, nil
	}
	return strconv.ParseUint(v, 10, 64)
}

// Validate implements CgroupDriver.
func (d *cgroupV1Driver) Validate(cgroup string) error {
	memoryPath := filepath.Join(d.root, "memory", cgroup)
	info, err := fs.Stat(d.fs, memoryPath)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
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

func DetectCgroupDriver() (CgroupDriver, error) {
	osFs := os.DirFS("/")

	// fast path: cgroup2 only
	var stat unix.Statfs_t
	if err := unix.Statfs("/sys/fs/cgroup", &stat); err != nil {
		return nil, err
	}
	if stat.Type == unix.CGROUP2_SUPER_MAGIC {
		return &cgroupV2Driver{root: "sys/fs/cgroup", fs: osFs}, nil
	}

	// find the hybrid mountpoint, or fall back to v1
	mountpoint, isV2, err := findMountpoint(osFs)
	if err != nil {
		return nil, err
	}
	if isV2 {
		return &cgroupV2Driver{root: mountpoint, fs: osFs}, nil
	}
	return &cgroupV1Driver{root: mountpoint, fs: osFs}, nil
}

func parseCgroupName(contents []byte) (string, error) {
	scan := bufio.NewScanner(bytes.NewReader(contents))
	for scan.Scan() {
		line := scan.Text()
		if strings.HasPrefix(line, "0::") {
			return strings.Split(strings.TrimPrefix(strings.TrimSpace(line), "0::"), " ")[0], nil
		}
	}
	return "", errors.New("cgroup not found")
}

func findMountpoint(fsys fs.FS) (mountpoint string, isV2 bool, err error) {
	mounts, err := fs.ReadFile(fsys, fmt.Sprintf("proc/%d/mountinfo", os.Getpid()))
	if err != nil {
		return "", false, err
	}
	scanner := bufio.NewScanner(bytes.NewReader(mounts))
	var cgv1Root string
	for scanner.Scan() {
		line := strings.Fields(scanner.Text())
		fsType := line[slices.Index(line, "-")+1]
		switch fsType {
		case "cgroup2":
			return line[4][1:], true, nil
		case "cgroup":
			if cgv1Root == "" {
				cgv1Root = filepath.Dir(line[4][1:])
			}
		}
	}
	if cgv1Root == "" {
		return "", false, errors.New("no cgroup mount found")
	}
	return cgv1Root, false, nil
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

	value atomic.Uint64

	watches sync.WaitGroup
}

func (w *memoryLimitWatcher) Value() uint64 {
	return w.value.Load()
}

func (w *memoryLimitWatcher) readValue() (uint64, error) {
	data, err := os.ReadFile(w.limitFilePath)
	if err != nil {
		return 0, err
	}
	v := strings.TrimSpace(string(data))
	if v == "max" {
		return 0, nil
	}
	return strconv.ParseUint(v, 10, 64)
}

func (w *memoryLimitWatcher) Watch(ctx context.Context) error {
	fd, err := unix.InotifyInit1(unix.IN_CLOEXEC)
	if err != nil {
		return err
	}
	closeInotify := sync.OnceFunc(func() {
		log.Ctx(ctx).Debug().Msg("stopping memory limit watcher")
		unix.Close(fd)
	})
	log.Ctx(ctx).Debug().Str("file", w.limitFilePath).Msg("starting watch")
	wd, err := unix.InotifyAddWatch(fd, w.limitFilePath, unix.IN_MODIFY)
	if err != nil {
		closeInotify()
		return fmt.Errorf("failed to watch %s: %w", w.limitFilePath, err)
	}
	w.watches.Add(1)
	closeWatch := sync.OnceFunc(func() {
		log.Ctx(ctx).Debug().Str("file", w.limitFilePath).Msg("stopping watch")
		_, _ = unix.InotifyRmWatch(fd, uint32(wd))
		closeInotify()
		w.watches.Done()
	})

	// perform the initial read synchronously and only after setting up the watch
	v, err := w.readValue()
	if err != nil {
		closeWatch()
		return err
	}
	w.value.Store(v)
	log.Ctx(ctx).Debug().Uint64("bytes", v).Msg("current memory limit")

	context.AfterFunc(ctx, closeWatch) // to unblock unix.Read below
	go func() {
		defer closeWatch()
		var buf [unix.SizeofInotifyEvent]byte
		for ctx.Err() == nil {
			v, err := w.readValue()
			if err != nil {
				log.Ctx(ctx).Error().Err(err).Msg("error reading memory limit")
			} else if prev := w.value.Swap(v); prev != v {
				log.Ctx(ctx).Debug().
					Uint64("prev", prev).
					Uint64("current", v).
					Msg("memory limit updated")
			}
			// After ctx is canceled, inotify_rm_watch sends an IN_IGNORED event,
			// which unblocks this read and allows the loop to exit.
			n, err := unix.Read(fd, buf[:])
			if err != nil {
				if errors.Is(err, unix.EINTR) {
					continue
				}
				return
			}
			if n == unix.SizeofInotifyEvent {
				event := (*unix.InotifyEvent)(unsafe.Pointer(&buf))
				if (event.Mask & unix.IN_IGNORED) != 0 {
					// watch was removed, or the file was deleted (this can happen if
					// the memory controller is removed from the parent's subtree_control)
					log.Ctx(ctx).Info().Str("file", w.limitFilePath).Msg("watched file removed")
					return
				}
			}
		}
	}()

	return nil
}

// Wait blocks until all watches have been closed.
//
// Example use:
//
//	ctx, ca := context.WithCancel(context.Background())
//	w := &memoryLimitWatcher{...}
//	w.Watch(ctx)
//	...
//	ca()
//	w.Wait() // blocks until the previous watch is closed
func (w *memoryLimitWatcher) Wait() {
	w.watches.Wait()
}
