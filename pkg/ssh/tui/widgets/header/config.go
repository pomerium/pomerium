package header

import "charm.land/lipgloss/v2"

type Config struct {
	Options
}

type Options struct {
	LeftAlignedSegments  []Segment
	RightAlignedSegments []Segment
}

type SegmentStyles struct {
	Base lipgloss.Style
}
