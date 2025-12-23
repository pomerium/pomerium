package header

import (
	"github.com/pomerium/pomerium/pkg/ssh/tui/core"
)

type Widget = core.Widget[*Model]

type Config struct {
	Options
}

type Options struct {
	LeftAlignedSegments  []HeaderSegment
	RightAlignedSegments []HeaderSegment
}
