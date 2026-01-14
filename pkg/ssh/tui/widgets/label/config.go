package label

import (
	"charm.land/lipgloss/v2"
)

type Config struct {
	Styles
	Options
}

type Styles struct {
	Foreground lipgloss.Style
}

type Options struct {
	Text   string
	HAlign lipgloss.Position
	VAlign lipgloss.Position
}
