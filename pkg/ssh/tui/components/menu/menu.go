package menu

import (
	"charm.land/bubbles/v2/help"
	"charm.land/bubbles/v2/key"
	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"
	uv "github.com/charmbracelet/ultraviolet"
	"github.com/charmbracelet/x/ansi"
	"github.com/pomerium/pomerium/pkg/ssh/tui/core"
	"github.com/pomerium/pomerium/pkg/ssh/tui/style"
)

type ContextMenuKeyMap struct {
	Next   key.Binding
	Prev   key.Binding
	Cancel key.Binding
	Select key.Binding
}

// FullHelp implements help.KeyMap.
func (k ContextMenuKeyMap) FullHelp() [][]key.Binding {
	return [][]key.Binding{{k.Next, k.Prev, k.Cancel, k.Select}}
}

// ShortHelp implements help.KeyMap.
func (k ContextMenuKeyMap) ShortHelp() []key.Binding {
	return []key.Binding{k.Next, k.Prev, k.Cancel, k.Select}
}

type Entry struct {
	Label      string
	OnSelected tea.Cmd
}

type Widget = core.Widget[*Model]

type Model struct {
	Hovered  int
	Bindings ContextMenuKeyMap

	entries       []Entry
	maxLabelWidth int
}

func (s *Model) ContentDimensions() (int, int) {
	return 6 + s.maxLabelWidth, 2 + len(s.entries) // TODO
}

func NewContextMenuModel() *Model {
	m := &Model{
		Bindings: ContextMenuKeyMap{
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
		},
	}
	return m
}

func (s *Model) SetEntries(entries []Entry) {
	s.entries = entries
	w := 0
	for _, e := range entries {
		w = max(w, lipgloss.Width(e.Label))
	}
	s.maxLabelWidth = w
}

func (s *Model) Update(msg tea.Msg) tea.Cmd {
	switch msg := msg.(type) {
	case tea.MouseClickMsg:
		index, ok := s.hitTest(msg.X, msg.Y)
		if !ok {
			return nil
		}
		s.Hovered = index
		// return tea.Batch(s.entries[s.Hovered].OnSelected, HideMenu)
	case tea.MouseReleaseMsg:
		index, ok := s.hitTest(msg.X, msg.Y)
		if !ok {
			return nil
		}
		s.Hovered = index
		return tea.Batch(s.entries[s.Hovered].OnSelected, HideMenu)
	case tea.MouseMotionMsg:
		index, ok := s.hitTest(msg.X, msg.Y)
		if !ok {
			return nil
		}
		s.Hovered = index
	case tea.KeyPressMsg:
		switch {
		case key.Matches(msg.Key(), s.Bindings.Prev):
			s.Hovered = max(0, s.Hovered-1)
		case key.Matches(msg.Key(), s.Bindings.Next):
			s.Hovered = min(len(s.entries)-1, s.Hovered+1)
		case key.Matches(msg.Key(), s.Bindings.Cancel):
			return HideMenu
		case key.Matches(msg.Key(), s.Bindings.Select):
			return tea.Batch(s.entries[s.Hovered].OnSelected, HideMenu)
		}
	}
	return nil
}

func (s *Model) hitTest(x int, y int) (int, bool) {
	if x == 0 || // left border
		y == 0 || // top border
		x == s.maxLabelWidth+1 || // right border
		y == len(s.entries)+1 { // bottom border
		return -1, false
	}
	if y-1 < len(s.entries) { // note: assumes border size of 1
		return y - 1, true
	}
	return -1, false
}

func (s *Model) Blur()               {}
func (s *Model) Focus()              {}
func (s *Model) Focused() bool       { return false }
func (s *Model) KeyMap() help.KeyMap { return nil }

var contextMenuStyle = lipgloss.NewStyle().
	Border(style.OuterBlockBorder).
	BorderForeground(ansi.BrightBlack).
	BorderBackground(ansi.Black).
	Background(ansi.Black)

var hoveredStyle = lipgloss.NewStyle().
	Foreground(ansi.BrightWhite).
	Background(ansi.BrightBlack).
	MarginBackground(ansi.Black).
	PaddingLeft(1).
	PaddingRight(1).
	MarginLeft(1).
	MarginRight(1)

var notHoveredStyle = lipgloss.NewStyle().
	Foreground(ansi.White).
	Background(ansi.Black).
	MarginBackground(ansi.Black).
	MarginLeft(2).
	MarginRight(2)

func (s *Model) OnResized(w, h int) {}

func (s *Model) View() uv.Drawable {
	labels := make([]string, 0, len(s.entries))
	for i, e := range s.entries {
		width := lipgloss.Width(e.Label)
		var style lipgloss.Style
		if s.Hovered == i {
			style = hoveredStyle
		} else {
			style = notHoveredStyle
		}
		if width < s.maxLabelWidth {
			style = style.PaddingRight(style.GetPaddingRight() + (s.maxLabelWidth - width))
		}
		labels = append(labels, style.Render(e.Label))
	}
	return uv.NewStyledString(contextMenuStyle.Render(lipgloss.JoinVertical(lipgloss.Left, labels...)))
}
