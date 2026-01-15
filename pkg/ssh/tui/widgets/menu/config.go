package menu

import (
	"charm.land/bubbles/v2/key"
	"charm.land/lipgloss/v2"

	"github.com/pomerium/pomerium/pkg/ssh/tui/style"
)

type Config struct {
	Styles
	Options
}

type Styles struct {
	Border            lipgloss.Style
	MenuEntry         lipgloss.Style
	SelectedMenuEntry lipgloss.Style
}

type Options struct {
	KeyMap KeyMap
}

var DefaultKeyMap = KeyMap{
	Prev: key.NewBinding(
		key.WithKeys("up", "k"),
		key.WithHelp("↑/k", "previous"),
	),
	Next: key.NewBinding(
		key.WithKeys("down", "j"),
		key.WithHelp("↓/j", "next"),
	),
	Cancel: key.NewBinding(
		key.WithKeys("esc", "q"),
		key.WithHelp("esc", "cancel"),
	),
	Select: key.NewBinding(
		key.WithKeys("enter", "space"),
		key.WithHelp("enter", "select"),
	),
}

func NewStyles(theme *style.Theme) Styles {
	return Styles{
		Border:            theme.ContextMenu,
		MenuEntry:         theme.ContextMenuEntry,
		SelectedMenuEntry: theme.ContextMenuSelectedEntry,
	}
}
