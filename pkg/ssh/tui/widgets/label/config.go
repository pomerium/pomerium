package label

import (
	"charm.land/lipgloss/v2"
	"github.com/pomerium/pomerium/pkg/ssh/tui/style"
)

type Config struct {
	Styles *style.ReactiveStyles[Styles]
	Options
}

type Styles struct {
	Normal  lipgloss.Style
	Focused lipgloss.Style
}

type Options struct {
	Text   string
	HAlign lipgloss.Position
	VAlign lipgloss.Position
}
