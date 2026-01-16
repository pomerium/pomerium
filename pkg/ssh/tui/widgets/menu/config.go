package menu

import (
	"charm.land/bubbles/v2/key"
	"charm.land/lipgloss/v2"

	uv "github.com/charmbracelet/ultraviolet"
	"github.com/pomerium/pomerium/pkg/ssh/tui/style"
)

type Config struct {
	Styles *style.ReactiveStyles[Styles]
}

type Styles struct {
	Border            lipgloss.Style
	MenuEntry         lipgloss.Style
	SelectedMenuEntry lipgloss.Style
}

type Options struct {
	Anchor  uv.Position
	Entries []Entry
	KeyMap  KeyMap
}

var DefaultKeyMap = KeyMap{
	Prev: key.NewBinding(
		key.WithKeys("up", "k", "shift+tab"),
		key.WithHelp("↑/k", "previous"),
	),
	Next: key.NewBinding(
		key.WithKeys("down", "j", "tab"),
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
