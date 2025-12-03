package logviewer

import (
	"charm.land/lipgloss/v2"
	"github.com/pomerium/pomerium/pkg/ssh/tui/core"
	"github.com/pomerium/pomerium/pkg/ssh/tui/style"
)

type Widget = core.Widget[*Model]

type Config struct {
	Styles
	Options
}

type Styles struct {
	Border        lipgloss.Style
	BorderFocused lipgloss.Style
	Timestamp     lipgloss.Style
}

type Options struct {
	BufferSize           int
	BorderTitleLeft      string
	BorderTitleRight     string
	ShowTimestamp        bool
	HideScrollbarButtons bool
	AlwaysShowScrollbar  bool
}

func NewStyles(theme *style.Theme, accentColor style.AccentColor) Styles {
	return Styles{
		Border:        lipgloss.NewStyle().Inherit(theme.Card),
		BorderFocused: lipgloss.NewStyle().Inherit(theme.Card).BorderForeground(accentColor.Normal),
		Timestamp:     lipgloss.NewStyle().Inherit(theme.TextTimestamp).Faint(true),
	}
}
