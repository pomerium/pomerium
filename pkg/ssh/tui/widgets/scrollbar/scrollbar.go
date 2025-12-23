package scrollbar

import (
	"fmt"
	"math"
	"slices"
)

type ScrollbarStyles struct {
	UpArrow, DownArrow rune
	Arrows             bool
}

type Scrollbar struct {
	height int // assumes the height is the same as the container's height
	styles ScrollbarStyles

	value    int
	maxValue int

	cachedRenderState renderState
}

func (s *Scrollbar) SetHeight(height int) {
	if s.height != height {
		s.height = height
		s.cachedRenderState = renderState{}
	}
}

func (s *Scrollbar) SetStyles(styles ScrollbarStyles) {
	if s.styles != styles {
		s.styles = styles
		s.cachedRenderState = renderState{}
	}
}

func (s *Scrollbar) SetValue(value int) {
	if s.value != value {
		s.value = min(value, s.maxValue)
		s.cachedRenderState = renderState{}
	}
}

func (s *Scrollbar) SetMaxValue(maxValue int) {
	if s.maxValue != maxValue {
		s.maxValue = maxValue
		s.value = min(s.value, s.maxValue)
		s.cachedRenderState = renderState{}
	}
}

// VisualPageSize returns the page size as represented visually by the slider
// compared to the track. The height of the slider has a minimum of 8
// "eighth-units" so this may return a larger page size than the real scroll
// area's page size. The value returned is the page size represented by one
// row of the slider.
func (s *Scrollbar) VisualPageSize() int {
	length := s.maxValue + s.height
	rows := s.height
	if s.styles.Arrows {
		rows -= 2
	}
	return int(math.Round(float64(length) / float64(rows)))
}

func (s *Scrollbar) VisualSliderPageSize() int {
	length := s.maxValue + s.height
	return length / (s.VisualPageSize())
}

type HitTestResult int

const (
	HitNone = iota
	HitUpButton
	HitTrackAboveSlider
	HitSlider
	HitTrackBelowSlider
	HitDownButton
)

func (s *Scrollbar) HitTest(y int) HitTestResult {
	if !s.cachedRenderState.Valid || y < 0 || y >= len(s.cachedRenderState.Rows) {
		return HitNone
	}
	switch s.cachedRenderState.Rows[y] {
	case s.styles.UpArrow:
		return HitUpButton
	case s.styles.DownArrow:
		return HitDownButton
	case '▃', '▄', '▅', '▆', '▇', '█', '🮆', '🮅', '🮄', '▀', '🮃':
		return HitSlider
	case '▁', '▂':
		return HitTrackAboveSlider
	case '▔', '🮂':
		return HitTrackBelowSlider
	case ' ':
		start := y * 8
		if s.styles.Arrows {
			start -= 8
		}
		if start < s.cachedRenderState.ValuePos {
			return HitTrackAboveSlider
		} else if start >= s.cachedRenderState.ValuePos+s.cachedRenderState.HandleHeight {
			return HitTrackBelowSlider
		}
	}
	panic(fmt.Sprintf("bug: invalid state in HitTest: y=%d; state=%#v", y, s.cachedRenderState))
}

type renderState struct {
	Valid        bool
	TrackHeight  int
	HandleHeight int
	ValuePos     int
	Rows         []rune
}

var (
	lowerBlocks = [...]rune{'▁', '▂', '▃', '▄', '▅', '▆', '▇'}
	upperBlocks = [...]rune{'▔', '🮂', '🮃', '▀', '🮄', '🮅', '🮆'}
)

func (s *Scrollbar) Rows() []rune {
	if s.height < 4 {
		return nil
	}
	if s.cachedRenderState.Valid {
		return s.cachedRenderState.Rows
	}
	trackHeight := s.height * 8
	if s.styles.Arrows {
		trackHeight = (s.height - 2) * 8
	}
	// The handle must have a minimum height of 8, since unicode does not have
	// center blocks(?)
	handleHeight := max(8, int(math.Round(float64(s.height)/float64(s.height+s.maxValue)*float64(trackHeight))))
	// 	handleHeight := max(8, ((s.height*trackHeight)+((s.height+s.maxValue)/2))/(s.height+s.maxValue))
	var valuePos int
	if s.maxValue > 0 {
		valuePos = int(math.Round(float64(s.value) / float64(s.maxValue) * float64(trackHeight-handleHeight)))
		// valuePos = (s.value*(trackHeight-handleHeight) + ((s.maxValue - 1) / 2)) / s.maxValue

		// ensure that the very top and bottom positions are reserved for the actual
		// minimum and maximum, ignoring rounding
		if valuePos == 0 && s.value > 0 {
			valuePos++
		} else if valuePos == trackHeight-handleHeight && s.value < s.maxValue {
			valuePos--
		}
	}

	above := valuePos
	below := trackHeight - handleHeight - valuePos

	rows := make([]rune, 0, s.height)
	if s.styles.Arrows {
		rows = append(rows, s.styles.UpArrow)
	}
	rows = append(rows, slices.Repeat([]rune{' '}, above/8)...)
	if above%8 != 0 {
		rows = append(rows, lowerBlocks[8-above%8-1])
	}
	rows = append(rows, slices.Repeat([]rune{'█'}, (handleHeight-((8-below%8)%8)-((8-above%8)%8))/8)...)
	if below%8 != 0 {
		rows = append(rows, upperBlocks[8-below%8-1])
	}
	rows = append(rows, slices.Repeat([]rune{' '}, below/8)...)
	if s.styles.Arrows {
		rows = append(rows, s.styles.DownArrow)
	}
	if len(rows) != s.height {
		panic(fmt.Sprintf("bug: wrong number of rows returned from Scrollbar.Rows: %#v", s))
	}
	s.cachedRenderState = renderState{
		Valid:        true,
		TrackHeight:  trackHeight,
		HandleHeight: handleHeight,
		ValuePos:     valuePos,
		Rows:         rows,
	}
	return rows
}
