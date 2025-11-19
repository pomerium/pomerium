package tui

import (
	"math"
	"slices"
)

type Scrollbar struct {
	Height int // assumes the height is the same as the container's height

	UpArrow, DownArrow rune
	Arrows             bool

	Value int
	Max   int
}

var (
	lowerBlocks = [...]rune{'▁', '▂', '▃', '▄', '▅', '▆', '▇'}
	upperBlocks = [...]rune{'▔', '🮂', '🮃', '▀', '🮄', '🮅', '🮆'}
	offsets     = [...]int{0, 7, 6, 5, 4, 3, 2, 1}
)

func (s Scrollbar) Rows() []rune {
	if s.Height < 3 {
		return nil
	}
	trackHeight := s.Height * 8
	if s.Arrows {
		trackHeight = (s.Height - 2) * 8
	}
	// The handle must have a minimum height of 8, since unicode does not have
	// center blocks(?)
	handleHeight := max(8, int(math.Round(float64(s.Height)/float64(s.Height+s.Max)*float64(trackHeight))))
	var valuePos int
	if s.Max > 0 {
		valuePos = int(math.Round(float64(s.Value) / float64(s.Max) * float64(trackHeight-handleHeight)))
		if valuePos == 0 && s.Value > 0 {
			valuePos++
		} else if valuePos == trackHeight-handleHeight && s.Value < s.Max {
			valuePos--
		}
	}

	above := valuePos
	below := trackHeight - handleHeight - valuePos

	rows := make([]rune, 0, s.Height)
	if s.Arrows {
		rows = append(rows, s.UpArrow)
	}
	rows = append(rows, slices.Repeat([]rune{' '}, above/8)...)
	if above%8 != 0 {
		rows = append(rows, lowerBlocks[8-above%8-1])
	}
	rows = append(rows, slices.Repeat([]rune{'█'}, (handleHeight-offsets[below%8]-offsets[above%8])/8)...)
	if below%8 != 0 {
		rows = append(rows, upperBlocks[8-below%8-1])
	}
	rows = append(rows, slices.Repeat([]rune{' '}, below/8)...)
	if s.Arrows {
		rows = append(rows, s.DownArrow)
	}
	return rows
}
