package dialog

import (
	"charm.land/bubbles/v2/key"
	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"
	"github.com/pomerium/pomerium/pkg/ssh/tui/core"
	"github.com/pomerium/pomerium/pkg/ssh/tui/style"
)

type Config struct {
	Styles *style.ReactiveStyles[Styles]
	Options
	Events
}

type Styles struct {
	Dialog         lipgloss.Style
	Footer         lipgloss.Style
	Button         lipgloss.Style
	SelectedButton lipgloss.Style
}

type Options struct {
	Contents         core.Widget
	Buttons          []ButtonConfig
	ButtonsAlignment lipgloss.Position
	KeyMap           KeyMap

	// If true, the dialog can be closed by clicking outside it or pressing esc
	Closeable bool
}

type Events struct {
	OnClosed func() tea.Cmd
}

var DefaultKeyMap = KeyMap{
	Close: key.NewBinding(
		key.WithKeys("esc"),
		key.WithHelp("esc", "close"),
	),
	Next: key.NewBinding(
		key.WithKeys("down", "j"),
		key.WithHelp("↓/j", "next"),
	),
	Prev: key.NewBinding(
		key.WithKeys("esc", "q"),
		key.WithHelp("esc", "cancel"),
	),
	Select: key.NewBinding(
		key.WithKeys("enter", "space"),
		key.WithHelp("enter", "select"),
	),
}

type ButtonConfig struct {
	Label   string
	Default bool
	OnClick func() tea.Cmd
}

func NewStyles(theme *style.Theme) Styles {
	return Styles{
		Dialog:         theme.Dialog,
		Button:         theme.Button,
		SelectedButton: theme.ButtonSelected,
	}
}

// Helper no-op command to use for OnClick
func Close() tea.Cmd { return nil }
