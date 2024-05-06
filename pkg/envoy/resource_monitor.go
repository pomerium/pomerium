package envoy

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"

	envoy_config_bootstrap_v3 "github.com/envoyproxy/go-control-plane/envoy/config/bootstrap/v3"
	envoy_config_overload_v3 "github.com/envoyproxy/go-control-plane/envoy/config/overload/v3"
	envoy_extensions_resource_monitors_injected_resource_v3 "github.com/envoyproxy/go-control-plane/envoy/extensions/resource_monitors/injected_resource/v3"
	typev3 "github.com/envoyproxy/go-control-plane/envoy/type/v3"
	"github.com/natefinch/atomic"
	"github.com/pomerium/pomerium/internal/log"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
)

const (
	groupMemory = "memory"

	metricCgroupMemoryUsageRatio = "cg_memory_usage_ratio"
)

type ResourceMonitor interface {
	Run(ctx context.Context, envoyPid int) error
	ApplyBootstrapConfig(bootstrap *envoy_config_bootstrap_v3.Bootstrap)
}

// NewSharedResourceMonitor creates a new ResourceMonitor suitable for running
// envoy in the same cgroup as the parent process. It reports the cgroup's
// memory usage ratio to envoy as an injected resource. This allows envoy to
// react to actual memory pressure in the cgroup, taking into account memory
// usage from pomerium itself.
func NewSharedResourceMonitor(tempDir string) (ResourceMonitor, error) {
	if ok, err := isCgroupsV2(); err != nil {
		return nil, fmt.Errorf("failed to determine cgroup version: %w", err)
	} else if !ok {
		return nil, errors.New("only cgroups v2 is supported")
	}

	selfCgroup, err := selfCgroup()
	if err != nil {
		return nil, fmt.Errorf("failed to look up cgroup: %w", err)
	}
	if err := validateCgroup(selfCgroup); err != nil {
		return nil, fmt.Errorf("cgroup not valid for resource monitoring: %w", err)
	}

	if err := os.MkdirAll(filepath.Join(tempDir, "resource_monitor", groupMemory), 0o755); err != nil {
		return nil, fmt.Errorf("failed to create resource monitor directory: %w", err)
	}

	s := &sharedResourceMonitor{
		cgroup:  selfCgroup,
		tempDir: filepath.Join(tempDir, "resource_monitor"),
	}
	if err := s.writeMetric(groupMemory, metricCgroupMemoryUsageRatio, "0", 0o644); err != nil {
		return nil, fmt.Errorf("failed to initialize metrics: %w", err)
	}
	return s, nil
}

type sharedResourceMonitor struct {
	cgroup  string
	tempDir string
}

func (s *sharedResourceMonitor) metricFilename(group, name string) string {
	return filepath.Join(s.tempDir, group, name)
}

func (s *sharedResourceMonitor) ApplyBootstrapConfig(bootstrap *envoy_config_bootstrap_v3.Bootstrap) {
	memUsageScaled := func(scaling, saturation float64) *envoy_config_overload_v3.Trigger {
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
	memUsageThreshold := func(threshold float64) *envoy_config_overload_v3.Trigger {
		return &envoy_config_overload_v3.Trigger{
			Name: "envoy.resource_monitors.injected_resource",
			TriggerOneof: &envoy_config_overload_v3.Trigger_Threshold{
				Threshold: &envoy_config_overload_v3.ThresholdTrigger{
					Value: threshold,
				},
			},
		}
	}

	if bootstrap.OverloadManager == nil {
		bootstrap.OverloadManager = &envoy_config_overload_v3.OverloadManager{}
	}

	bootstrap.OverloadManager.ResourceMonitors = append(bootstrap.OverloadManager.ResourceMonitors,
		&envoy_config_overload_v3.ResourceMonitor{
			Name: "envoy.resource_monitors.injected_resource",
			ConfigType: &envoy_config_overload_v3.ResourceMonitor_TypedConfig{
				TypedConfig: marshalAny(&envoy_extensions_resource_monitors_injected_resource_v3.InjectedResourceConfig{
					Filename: s.metricFilename(groupMemory, metricCgroupMemoryUsageRatio),
				}),
			},
		},
	)

	bootstrap.OverloadManager.Actions = append(bootstrap.OverloadManager.Actions,
		&envoy_config_overload_v3.OverloadAction{
			Name:     "envoy.overload_actions.shrink_heap",
			Triggers: []*envoy_config_overload_v3.Trigger{memUsageScaled(0.8, 0.9)},
		},
		&envoy_config_overload_v3.OverloadAction{
			Name:     "envoy.overload_actions.reduce_timeouts",
			Triggers: []*envoy_config_overload_v3.Trigger{memUsageScaled(0.85, 0.95)},
			TypedConfig: marshalAny(&envoy_config_overload_v3.ScaleTimersOverloadActionConfig{
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
		},
		&envoy_config_overload_v3.OverloadAction{
			Name:     "envoy.overload_actions.reset_high_memory_stream",
			Triggers: []*envoy_config_overload_v3.Trigger{memUsageScaled(0.90, 0.95)},
		},
		&envoy_config_overload_v3.OverloadAction{
			Name:     "envoy.overload_actions.stop_accepting_connections",
			Triggers: []*envoy_config_overload_v3.Trigger{memUsageThreshold(0.95)},
		},
		&envoy_config_overload_v3.OverloadAction{
			Name:     "envoy.overload_actions.disable_http_keepalive",
			Triggers: []*envoy_config_overload_v3.Trigger{memUsageThreshold(0.97)},
		},
		&envoy_config_overload_v3.OverloadAction{
			Name:     "envoy.overload_actions.stop_accepting_requests",
			Triggers: []*envoy_config_overload_v3.Trigger{memUsageThreshold(0.99)},
		},
	)

	bootstrap.OverloadManager.BufferFactoryConfig = &envoy_config_overload_v3.BufferFactoryConfig{
		MinimumAccountToTrackPowerOfTwo: 20,
	}
}

func (s *sharedResourceMonitor) Run(ctx context.Context, envoyPid int) error {
	envoyCgroup, err := cgroupForPid(envoyPid)
	if err != nil {
		return fmt.Errorf("failed to look up cgroup for envoy process: %w", err)
	}
	if envoyCgroup != s.cgroup {
		return fmt.Errorf("envoy process is not in the expected cgroup: %s", envoyCgroup)
	}

	// The interval at which we check memory usage is scaled based on the current
	// memory usage ratio. When memory usage is low, we check less frequently, and
	// as the ratio increases, we also increase the frequency of checks. Most of
	// the thresholds at which some action is taken to reduce memory usage are
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
			ratio, err := s.calcMemUsageRatio()
			if err != nil {
				log.Error(ctx).Err(err).Msg("failed to get memory usage ratio")
				continue
			}
			ratioStr := fmt.Sprintf("%.6f", ratio)
			nextInterval := (maxTickDuration - (time.Duration(float64(maxTickDuration-minTickDuration) * ratio))).Round(time.Millisecond)

			if ratioStr != lastValue {
				lastValue = ratioStr
				s.writeMetric(groupMemory, metricCgroupMemoryUsageRatio, ratioStr, 0o644)
				log.Debug(ctx).
					Str("service", "envoy").
					Str("metric", metricCgroupMemoryUsageRatio).
					Str("value", ratioStr).
					Dur("interval_ms", nextInterval).
					Msg("updated metric")
			}

			tick.Reset(nextInterval)
		}
	}
}

func (s *sharedResourceMonitor) writeMetric(group, name, data string, mode fs.FileMode) error {
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
	if err := atomic.ReplaceFile(tempFilename, filepath.Join(s.tempDir, group, name)); err != nil {
		return err
	}
	return nil
}

const cgroupRoot = "/sys/fs/cgroup"

func (s *sharedResourceMonitor) calcMemUsageRatio() (float64, error) {
	path := filepath.Join(cgroupRoot, s.cgroup, "memory.current")
	current, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	max, err := os.ReadFile(filepath.Join(cgroupRoot, s.cgroup, "memory.max"))
	if err != nil {
		return 0, err
	}
	if string(max) == "max" {
		// no limit set
		return 0, nil
	}
	curNum, err := strconv.ParseUint(strings.TrimSpace(string(current)), 10, 64)
	if err != nil {
		return 0, err
	}
	maxNum, err := strconv.ParseUint(strings.TrimSpace(string(max)), 10, 64)
	if err != nil {
		return 0, err
	}
	return float64(curNum) / float64(maxNum), nil
}

func cgroupForPid(pid int) (string, error) {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/cgroup", pid))
	if err != nil {
		return "", err
	}
	return parseCgroupName(data), nil
}

func selfCgroup() (string, error) {
	data, err := os.ReadFile("/proc/self/cgroup")
	if err != nil {
		return "", err
	}
	return parseCgroupName(data), nil
}

func parseCgroupName(contents []byte) string {
	return strings.Split(strings.TrimPrefix(strings.TrimSpace(string(contents)), "0::"), " ")[0]
}

func isCgroupsV2() (bool, error) {
	const cgv2Magic = 0x63677270
	for {
		var stat syscall.Statfs_t
		err := syscall.Statfs(cgroupRoot, &stat)
		if err != nil {
			if err == syscall.EINTR {
				continue
			}
			return false, err
		}
		return stat.Type == cgv2Magic, nil
	}
}

func validateCgroup(cgroup string) error {
	if typ, err := os.ReadFile(filepath.Join(cgroupRoot, cgroup, "cgroup.type")); err != nil {
		return err
	} else if strings.TrimSpace(string(typ)) != "domain" {
		return errors.New("not a domain cgroup")
	}

	if controllers, err := enabledSubtreeControllers(cgroup); err != nil {
		return err
	} else if len(controllers) > 0 {
		return errors.New("not a leaf cgroup")
	}

	if controllers, err := enabledControllers(cgroup); err != nil {
		return err
	} else if !slices.Contains(controllers, "memory") {
		return errors.New("memory controller not enabled")
	}

	return nil
}

func enabledControllers(cgroup string) ([]string, error) {
	data, err := os.ReadFile(filepath.Join(cgroupRoot, cgroup, "cgroup.controllers"))
	if err != nil {
		return nil, err
	}
	return strings.Fields(string(data)), nil
}

func enabledSubtreeControllers(cgroup string) ([]string, error) {
	data, err := os.ReadFile(filepath.Join(cgroupRoot, cgroup, "cgroup.subtree_control"))
	if err != nil {
		return nil, err
	}
	return strings.Fields(string(data)), nil
}

func marshalAny(msg proto.Message) *anypb.Any {
	data := new(anypb.Any)
	_ = anypb.MarshalFrom(data, msg, proto.MarshalOptions{
		AllowPartial:  true,
		Deterministic: true,
	})
	return data
}
