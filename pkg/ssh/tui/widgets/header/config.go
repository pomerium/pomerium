package header

type Config struct {
	Options
}

type Options struct {
	LeftAlignedSegments  []HeaderSegment
	RightAlignedSegments []HeaderSegment
}
