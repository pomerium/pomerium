package health

import "github.com/pomerium/pomerium/pkg/slices"

type Filter struct {
	Exclude []Check `mapstructure:"exclude" yaml:"exclude"`
}

func MergeFilters(f1, f2 Filter) Filter {
	return Filter{
		Exclude: slices.Unique(append(f1.Exclude, f2.Exclude...)),
	}
}

type CheckOptions struct {
	expected map[Check]struct{}
}

func (o *CheckOptions) Apply(opts ...CheckOption) {
	for _, opt := range opts {
		opt(o)
	}
}

type CheckOption func(o *CheckOptions)

func WithExpectedChecks(
	checks ...Check,
) CheckOption {
	return func(o *CheckOptions) {
		if o.expected == nil {
			o.expected = map[Check]struct{}{}
		}
		for _, check := range checks {
			o.expected[check] = struct{}{}
		}
	}
}
