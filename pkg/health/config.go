package health

import "github.com/samber/lo"

type Filter struct {
	Exclude []Check `mapstructure:"exclude" yaml:"exclude"`
}

func MergeFilters(f1, f2 Filter) Filter {
	return Filter{
		Exclude: lo.Uniq(append(f1.Exclude, f2.Exclude...)),
	}
}

type HTTPProbeConfig struct {
	Filter `mapstructure:",squash" yaml:",inline"`
}

type HTTPConfig struct {
	StartupProbe    *HTTPProbeConfig `mapstructure:"startup_probe" yaml:"startup_probe"`
	ReadinessProbe  *HTTPProbeConfig `mapstructure:"readiness_probe" yaml:"readiness_probe"`
	LivelinessProbe *HTTPProbeConfig `mapstructure:"liveliness_probe" yaml:"liveliness_probe"`
}
