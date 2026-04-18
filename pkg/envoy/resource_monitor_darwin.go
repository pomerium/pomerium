//go:build darwin

package envoy

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	envoy_config_bootstrap_v3 "github.com/envoyproxy/go-control-plane/envoy/config/bootstrap/v3"
	envoy_config_overload_v3 "github.com/envoyproxy/go-control-plane/envoy/config/overload/v3"
	envoy_extensions_resource_monitors_injected_resource_v3 "github.com/envoyproxy/go-control-plane/envoy/extensions/resource_monitors/injected_resource/v3"
	typev3 "github.com/envoyproxy/go-control-plane/envoy/type/v3"
	"golang.org/x/sys/unix"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/internal/telemetry/metrics"
)

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
	driver DarwinMemoryDriver
}

type ResourceMonitorOption func(*ResourceMonitorOptions)

func (o *ResourceMonitorOptions) apply(opts ...ResourceMonitorOption) {
	for _, op := range opts {
		op(o)
	}
}

// WithDarwinMemoryDriver overrides the memory driver used for the resource monitor.
// If unset, it will be chosen automatically.
func WithDarwinMemoryDriver(driver DarwinMemoryDriver) ResourceMonitorOption {
	return func(o *ResourceMonitorOptions) {
		o.driver = driver
	}
}

// NewSharedResourceMonitor creates a new ResourceMonitor suitable for running
// envoy in a process on Darwin. It reports the process memory usage as a percentage
// of available system memory to envoy as an injected resource. This allows envoy to
// react to actual memory pressure.
func NewSharedResourceMonitor(ctx context.Context, src config.Source, tempDir string, opts ...ResourceMonitorOption) (ResourceMonitor, error) {
	options := ResourceMonitorOptions{}
	options.apply(opts...)
	if options.driver == nil {
		var err error
		options.driver, err = DetectDarwinMemoryDriver()
		if err != nil {
			return nil, err
		}
	}
	recordActionThresholds()

	if err := os.MkdirAll(filepath.Join(tempDir, "resource_monitor", groupMemory), 0o755); err != nil {
		return nil, fmt.Errorf("failed to create resource monitor directory: %w", err)
	}

	s := &sharedResourceMonitorDarwin{
		ResourceMonitorOptions: options,
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

type sharedResourceMonitorDarwin struct {
	ResourceMonitorOptions
	tempDir string
	enabled atomic.Bool
}

func (s *sharedResourceMonitorDarwin) onConfigChange(_ context.Context, cfg *config.Config) {
	if cfg == nil || cfg.Options == nil {
		s.enabled.Store(config.DefaultRuntimeFlags()[config.RuntimeFlagEnvoyResourceManager])
		return
	}
	s.enabled.Store(cfg.Options.IsRuntimeFlagSet(config.RuntimeFlagEnvoyResourceManager))
}

func (s *sharedResourceMonitorDarwin) metricFilename(group, name string) string {
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

func (s *sharedResourceMonitorDarwin) ApplyBootstrapConfig(bootstrap *envoy_config_bootstrap_v3.Bootstrap) {
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

const (
	monitorInitialTickDelay = 1 * time.Second
	monitorMaxTickInterval  = 10 * time.Second
	monitorMinTickInterval  = 250 * time.Millisecond
)

func (s *sharedResourceMonitorDarwin) Run(ctx context.Context, _ int) error {
	log.Ctx(ctx).Debug().Str("service", "envoy").Msg("starting resource monitor (Darwin)")

	ctx, ca := context.WithCancelCause(ctx)

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

	tick := time.NewTimer(monitorInitialTickDelay)
	var lastValue string
	var systemMemory uint64
	var err error

	// Get system memory once at startup
	if systemMemory, err = s.driver.SystemMemory(); err != nil {
		ca(fmt.Errorf("failed to get system memory: %w", err))
		return fmt.Errorf("failed to get system memory: %w", err)
	}
	log.Ctx(ctx).Debug().Uint64("system_memory_bytes", systemMemory).Msg("system memory")

LOOP:
	for {
		select {
		case <-ctx.Done():
			tick.Stop()
			break LOOP
		case <-tick.C:
			var saturation float64
			if s.enabled.Load() {
				if systemMemory > 0 {
					procMemory, err := s.driver.ProcessMemory()
					if err != nil {
						log.Ctx(ctx).Error().Err(err).Msg("failed to get process memory")
						continue
					}
					saturation = max(0.0, min(1.0, float64(procMemory)/float64(systemMemory)))
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
				metrics.RecordEnvoyCgroupMemorySaturation(ctx, "darwin", saturation)
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

	return context.Cause(ctx)
}

// Returns a value between monitorMinTickInterval and monitorMaxTickInterval, based
// on the given saturation value in the range [0.0, 1.0].
func computeScaledTickInterval(saturation float64) time.Duration {
	return monitorMaxTickInterval - (time.Duration(float64(monitorMaxTickInterval-monitorMinTickInterval) * max(0.0, min(1.0, saturation)))).
		Round(time.Millisecond)
}

func (s *sharedResourceMonitorDarwin) updateActionStates(ctx context.Context, pct float64) {
	for name, minThreshold := range computedActionThresholds {
		var state int64
		if pct >= minThreshold {
			state = 1
		}
		metrics.RecordEnvoyOverloadActionState(ctx,
			metrics.EnvoyOverloadActionStateTags{
				Cgroup:     "darwin",
				ActionName: name,
			},
			state,
		)
	}
}

// writeMetricFile writes the saturation metric to a file atomically.
//
// The atomic operation is performed by writing to a temp file in the parent directory,
// then renaming it into place. We avoid writing directly to the target path because
// envoy watches the parent directory and would trigger an inotify event for the new
// file, causing reconfigurations.
func (s *sharedResourceMonitorDarwin) writeMetricFile(group, name, data string, mode os.FileMode) error {
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
	if err := unix.Rename(tempFilename, filepath.Join(s.tempDir, group, name)); err != nil {
		return err
	}
	return nil
}

type DarwinMemoryDriver interface {
	SystemMemory() (uint64, error)
	ProcessMemory() (uint64, error)
}

type defaultDarwinDriver struct{}

// SystemMemory queries the platform for total system memory size using a platform-specific
// sysctl. No standard library equivalent exists - this is the only reliable way to get
// total system memory on Darwin.
func (d *defaultDarwinDriver) SystemMemory() (uint64, error) {
	memsize, err := unix.SysctlUint64("hw.memsize")
	if err != nil {
		return 0, fmt.Errorf("failed to get system memory: %w", err)
	}
	return memsize, nil
}

// ProcessMemory retrieves the process's resident set size (RSS) using getrusage().
// No stdlib equivalent exists for getting physical memory usage - ReadMemStats can't
// measure RSS, only allocator statistics.
func (d *defaultDarwinDriver) ProcessMemory() (uint64, error) {
	var rusage unix.Rusage
	if err := unix.Getrusage(unix.RUSAGE_SELF, &rusage); err != nil {
		return 0, fmt.Errorf("failed to get process memory: %w", err)
	}
	return uint64(rusage.Maxrss) * 1024, nil
}

func DetectDarwinMemoryDriver() (DarwinMemoryDriver, error) {
	return &defaultDarwinDriver{}, nil
}

var _ DarwinMemoryDriver = (*defaultDarwinDriver)(nil)

func marshalAny(msg proto.Message) *anypb.Any {
	data := new(anypb.Any)
	_ = anypb.MarshalFrom(data, msg, proto.MarshalOptions{
		AllowPartial:  true,
		Deterministic: true,
	})
	return data
}