package table

import (
	"charm.land/bubbles/v2/key"
	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"
	uv "github.com/charmbracelet/ultraviolet"
	"github.com/pomerium/pomerium/pkg/ssh/models"
	"github.com/pomerium/pomerium/pkg/ssh/tui/core/layout"
	"github.com/pomerium/pomerium/pkg/ssh/tui/style"
)

type Config[T models.Item[K], K comparable] struct {
	Styles
	Options
	Events[T, K]
}

type Styles struct {
	Header        lipgloss.Style
	Cell          lipgloss.Style
	Selected      lipgloss.Style
	Border        lipgloss.Style
	BorderFocused lipgloss.Style
}

type Options struct {
	ColumnLayout     layout.DirectionalLayout
	KeyMap           KeyMap
	BorderTitleLeft  string
	BorderTitleRight string
}

type Events[T models.Item[K], K comparable] struct {
	// Right click/enter
	OnRowMenuRequested func(self *Model[T, K], globalPos uv.Position, index int) tea.Cmd
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
	HalfPageUp: key.NewBinding(
		key.WithKeys("u", "ctrl+u"),
		key.WithHelp("u", "½ page up"),
	),
	HalfPageDown: key.NewBinding(
		key.WithKeys("d", "ctrl+d"),
		key.WithHelp("d", "½ page down"),
	),
	GotoTop: key.NewBinding(
		key.WithKeys("home", "g"),
		key.WithHelp("g/home", "go to start"),
	),
	GotoBottom: key.NewBinding(
		key.WithKeys("end", "G"),
		key.WithHelp("G/end", "go to end"),
	),
	Deselect: key.NewBinding(
		key.WithKeys("esc"),
		key.WithHelp("esc", "deselect row"),
	),
	MenuRequest: key.NewBinding(
		key.WithKeys("enter"),
		key.WithHelp("enter/rmb", "context menu"),
	),
}

func NewStyles(theme *style.Theme, accentColor style.AccentColor) Styles {
	return Styles{
		Header:        lipgloss.NewStyle().Inherit(theme.TableHeader).PaddingLeft(1),
		Cell:          lipgloss.NewStyle().Inherit(theme.TableCell).PaddingLeft(1),
		Selected:      lipgloss.NewStyle().Inherit(theme.TableSelectedCell).PaddingLeft(1),
		Border:        lipgloss.NewStyle().Inherit(theme.Card),
		BorderFocused: lipgloss.NewStyle().Inherit(theme.Card).BorderForeground(accentColor.Normal),
	}
}
