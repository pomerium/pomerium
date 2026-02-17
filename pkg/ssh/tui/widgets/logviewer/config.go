package logviewer

import (
	"charm.land/bubbles/v2/key"
	"charm.land/lipgloss/v2"

	"github.com/pomerium/pomerium/pkg/ssh/tui/style"
)

type Config struct {
	Styles *style.ReactiveStyles[Styles]
	Options
}

type Styles struct {
	Border          lipgloss.Style
	BorderFocused   lipgloss.Style
	Timestamp       lipgloss.Style
	RepeatIndicator lipgloss.Style
	Text            lipgloss.Style
}

type Options struct {
	KeyMap               KeyMap
	BufferSize           int
	BorderTitleLeft      string
	BorderTitleRight     string
	ShowTimestamp        bool
	HideScrollbarButtons bool
	AlwaysShowScrollbar  bool
}

var DefaultKeyMap = KeyMap{
	LineUp: key.NewBinding(
		key.WithKeys("up", "k"),
		key.WithHelp("↑/k", "up"),
	),
	LineDown: key.NewBinding(
		key.WithKeys("down", "j"),
		key.WithHelp("↓/j", "down"),
	),
	PageUp: key.NewBinding(
		key.WithKeys("b", "pgup"),
		key.WithHelp("b/pgup", "page up"),
	),
	PageDown: key.NewBinding(
		key.WithKeys("f", "pgdown", "space"),
		key.WithHelp("f/pgdn", "page down"),
	),
	GotoTop: key.NewBinding(
		key.WithKeys("home", "g"),
		key.WithHelp("g/home", "go to start"),
	),
	GotoBottom: key.NewBinding(
		key.WithKeys("end", "G"),
		key.WithHelp("G/end", "go to end"),
	),
}

func NewStyles(theme *style.Theme, accentColor style.AccentColor) Styles {
	return Styles{
		Border:          theme.Card,
		BorderFocused:   theme.Card.BorderForeground(accentColor.Normal),
		Timestamp:       theme.TextTimestamp.Faint(true),
		RepeatIndicator: theme.TextNotice,
		Text:            theme.TextNormal,
	}
}
