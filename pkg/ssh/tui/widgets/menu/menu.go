package menu

import (
	"charm.land/bubbles/v2/help"
	"charm.land/bubbles/v2/key"
	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"
	uv "github.com/charmbracelet/ultraviolet"
	"github.com/pomerium/pomerium/pkg/ssh/tui/core"
)

type KeyMap struct {
	Next   key.Binding
	Prev   key.Binding
	Cancel key.Binding
	Select key.Binding
}

// FullHelp implements help.KeyMap.
func (k KeyMap) FullHelp() [][]key.Binding {
	return [][]key.Binding{{k.Next, k.Prev, k.Cancel, k.Select}}
}

// ShortHelp implements help.KeyMap.
func (k KeyMap) ShortHelp() []key.Binding {
	return []key.Binding{k.Next, k.Prev, k.Cancel, k.Select}
}

type Entry struct {
	Label      string
	OnSelected tea.Cmd
}

type Model struct {
	core.BaseModel
	config Config

	hovered       int
	entries       []Entry
	maxLabelWidth int
}

func (s *Model) ContentDimensions() (int, int) {
	return s.maxLabelWidth + s.config.Border.GetHorizontalFrameSize() + s.config.MenuEntry.GetHorizontalFrameSize(),
		len(s.entries) + s.config.Border.GetVerticalFrameSize()
}

func NewContextMenuModel(config Config) *Model {
	m := &Model{
		config: config,
	}
	return m
}

// Reset sets the menu entries and resets hover state. len(entries) must be > 0
func (s *Model) Reset(entries []Entry) {
	s.hovered = 0
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
		global := uv.Pos(msg.X, msg.Y)
		local := s.Parent().TranslateGlobalToLocalPos(global)

		index, ok := s.hitTest(local)
		if !ok {
			return nil
		}
		s.hovered = index
	case tea.MouseReleaseMsg:
		global := uv.Pos(msg.X, msg.Y)
		local := s.Parent().TranslateGlobalToLocalPos(global)

		index, ok := s.hitTest(local)
		if !ok {
			return nil
		}
		s.hovered = index
		return tea.Batch(s.entries[s.hovered].OnSelected, HideMenu)
	case tea.MouseMotionMsg:
		global := uv.Pos(msg.X, msg.Y)
		local := s.Parent().TranslateGlobalToLocalPos(global)

		index, ok := s.hitTest(local)
		if !ok {
			return nil
		}
		s.hovered = index
	case tea.KeyPressMsg:
		switch {
		case key.Matches(msg.Key(), s.config.KeyMap.Prev):
			s.hovered = max(0, s.hovered-1)
		case key.Matches(msg.Key(), s.config.KeyMap.Next):
			s.hovered = min(len(s.entries)-1, s.hovered+1)
		case key.Matches(msg.Key(), s.config.KeyMap.Cancel):
			return HideMenu
		case key.Matches(msg.Key(), s.config.KeyMap.Select):
			return tea.Batch(s.entries[s.hovered].OnSelected, HideMenu)
		}
	}
	return nil
}

func (s *Model) hitTest(localPos uv.Position) (int, bool) {
	rect := uv.Rect(
		s.config.Border.GetBorderLeftSize()+s.config.SelectedMenuEntry.GetMarginLeft(),
		s.config.Border.GetBorderTopSize(), // assumes no vertical padding
		s.maxLabelWidth+s.config.SelectedMenuEntry.GetHorizontalPadding(),
		len(s.entries))
	if localPos.In(rect) {
		return localPos.Y - rect.Min.Y, true
	}
	return -1, false
}

func (s *Model) Blur()         {}
func (s *Model) Focus()        {}
func (s *Model) Focused() bool { return false }
func (s *Model) KeyMap() help.KeyMap {
	// This is normally called when Focused() returns true, to control what is
	// displayed in the help panel. Because the context menu is modal, it doesn't
	// use the same focus mechanism as the other panels and instead is a special
	// case. We can still call KeyMap() to get the bindings though
	return s.config.KeyMap
}

func (s *Model) OnResized(w, h int) {}

func (s *Model) View() uv.Drawable {
	labels := make([]string, 0, len(s.entries))
	for i, e := range s.entries {
		width := lipgloss.Width(e.Label)
		var style lipgloss.Style
		if s.hovered == i {
			style = s.config.SelectedMenuEntry
		} else {
			style = s.config.MenuEntry
		}
		if width < s.maxLabelWidth {
			style = style.PaddingRight(style.GetPaddingRight() + (s.maxLabelWidth - width))
		}
		labels = append(labels, style.Render(e.Label))
	}
	return uv.NewStyledString(s.config.Border.Render(lipgloss.JoinVertical(lipgloss.Left, labels...)))
}
