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
}

type Styles struct {
	Dialog         lipgloss.Style
	DialogFlash    lipgloss.Style
	Footer         lipgloss.Style
	Button         lipgloss.Style
	SelectedButton lipgloss.Style
}

type Options struct {
	Contents         core.Widget
	Buttons          []ButtonConfig
	ButtonsAlignment lipgloss.Position
	KeyMap           KeyMap

	// If false, the dialog can be closed by clicking outside it or pressing esc
	ActionRequired bool
}

var DefaultKeyMap = KeyMap{
	Close: key.NewBinding(
		key.WithKeys("esc"),
		key.WithHelp("esc", "close"),
	),
	Next: key.NewBinding(
		key.WithKeys("tab", "right"),
		key.WithHelp("tab", "next button"),
	),
	Prev: key.NewBinding(
		key.WithKeys("shift+tab", "left"),
		key.WithHelp("shift+tab", "previous button"),
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
		DialogFlash:    theme.DialogFlash,
		Button:         theme.Button.Background(theme.Dialog.GetBackground()),
		SelectedButton: theme.ButtonSelected,
	}
}

// Helper no-op command to use for OnClick
func Close() tea.Cmd { return nil }
