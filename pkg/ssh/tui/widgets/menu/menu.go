package menu

import (
	"slices"

	"charm.land/bubbles/v2/help"
	"charm.land/bubbles/v2/key"
	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"
	uv "github.com/charmbracelet/ultraviolet"

	"github.com/pomerium/pomerium/pkg/ssh/tui/core"
	"github.com/pomerium/pomerium/pkg/ssh/tui/tunnel_status/messages"
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
	Label                    string
	OnSelected               func() tea.Cmd
	RequiresClipboardSupport bool
}

type Model struct {
	core.BaseModel
	config  Config
	options Options

	focused          bool
	hovered          int
	maxLabelWidth    int
	interceptor      *messages.ModalInterceptor
	deviceAttributes core.DeviceAttributes
}

func (m *Model) SizeHint() (int, int) {
	x := m.maxLabelWidth +
		m.config.Styles.Style().Border.GetHorizontalFrameSize() +
		m.config.Styles.Style().MenuEntry.GetHorizontalFrameSize()
	y := len(m.options.Entries) + m.config.Styles.Style().Border.GetVerticalFrameSize()
	return x, y
}

func NewContextMenuModel(config Config) *Model {
	m := &Model{
		config: config,
	}
	return m
}

// Reset sets the menu entries and resets hover state. len(entries) must be > 0
func (m *Model) Reset(options Options) {
	options.Entries = slices.DeleteFunc(options.Entries, func(e Entry) bool {
		return e.RequiresClipboardSupport && !m.deviceAttributes.ClipboardSupport
	})
	m.options = options
	m.options.KeyMap.Next.SetEnabled(len(options.Entries) > 1)
	m.options.KeyMap.Prev.SetEnabled(len(options.Entries) > 1)
	m.hovered = 0
	w := 0
	for _, e := range m.options.Entries {
		w = max(w, lipgloss.Width(e.Label))
	}
	m.maxLabelWidth = w
	mouseMode := tea.MouseModeAllMotion
	m.interceptor = &messages.ModalInterceptor{
		Update:            m.Update,
		KeyMap:            m.options.KeyMap,
		Scrim:             false,
		MouseModeOverride: &mouseMode,
	}
}

func (m *Model) Update(msg tea.Msg) tea.Cmd {
	switch msg := msg.(type) {
	case tea.MouseMsg:
		if !m.focused {
			return nil
		}
		global := uv.Pos(msg.Mouse().X, msg.Mouse().Y)
		local, inBounds := m.Parent().TranslateGlobalToLocalPos(global)
		if !inBounds {
			switch msg.(type) {
			case tea.MouseClickMsg:
				return m.hide(true)
			case tea.MouseReleaseMsg:
				// We may get a mouse release immediately in/around the anchor point
				if global.In(uv.Rect(m.options.Anchor.X-1, m.options.Anchor.Y-1, 3, 2)) {
					return nil
				}
				return m.hide(true)
			default:
				// ignore motion/scroll messages outside of the menu
				return nil
			}
		}
		index, ok := m.hitTest(local)
		if !ok {
			return nil
		}
		switch msg.(type) {
		case tea.MouseClickMsg:
			m.hovered = index
		case tea.MouseReleaseMsg:
			m.hovered = index
			return tea.Sequence(m.hide(false), m.options.Entries[m.hovered].OnSelected())
		case tea.MouseMotionMsg:
			m.hovered = index
		}
	case tea.KeyPressMsg:
		if !m.focused {
			return nil
		}
		switch {
		case key.Matches(msg.Key(), m.options.KeyMap.Prev):
			m.hovered = max(0, m.hovered-1)
		case key.Matches(msg.Key(), m.options.KeyMap.Next):
			m.hovered = min(len(m.options.Entries)-1, m.hovered+1)
		case key.Matches(msg.Key(), m.options.KeyMap.Cancel):
			return m.hide(false)
		case key.Matches(msg.Key(), m.options.KeyMap.Select):
			return tea.Sequence(m.hide(false), m.options.Entries[m.hovered].OnSelected())
		}
	case uv.PrimaryDeviceAttributesEvent:
		attrs := core.DeviceAttributes{}
		for _, attr := range msg {
			if attr == 52 {
				attrs.ClipboardSupport = true
			}
		}
		m.deviceAttributes = attrs
	}
	return nil
}

func (m *Model) hitTest(localPos uv.Position) (int, bool) {
	rect := uv.Rect(
		m.config.Styles.Style().Border.GetBorderLeftSize()+m.config.Styles.Style().SelectedMenuEntry.GetMarginLeft(),
		m.config.Styles.Style().Border.GetBorderTopSize(), // assumes no vertical padding
		m.maxLabelWidth+m.config.Styles.Style().SelectedMenuEntry.GetHorizontalPadding(),
		len(m.options.Entries))
	if localPos.In(rect) {
		return localPos.Y - rect.Min.Y, true
	}
	return -1, false
}

func (m *Model) Blur() tea.Cmd {
	return m.hide(false)
}

func (m *Model) Focus() tea.Cmd {
	return m.show()
}

func (m *Model) hide(ignoreNextMouseRelease bool) tea.Cmd {
	if !m.focused {
		return nil
	}
	m.focused = false
	return messages.ModalRelease(m.interceptor, ignoreNextMouseRelease)
}

func (m *Model) show() tea.Cmd {
	if m.focused {
		return nil
	}
	m.focused = true
	return messages.ModalAcquire(m.interceptor)
}

func (m *Model) Focused() bool { return m.focused }
func (m *Model) KeyMap() help.KeyMap {
	// This is normally called when Focused() returns true, to control what is
	// displayed in the help panel. Because the context menu is modal, it doesn't
	// use the same focus mechanism as the other panels and instead is a special
	// case. We can still call KeyMap() to get the bindings though
	return m.options.KeyMap
}

func (m *Model) OnResized(w, h int) {}

func (m *Model) View() uv.Drawable {
	labels := make([]string, 0, len(m.options.Entries))
	for i, e := range m.options.Entries {
		width := lipgloss.Width(e.Label)
		var style lipgloss.Style
		if m.hovered == i {
			style = m.config.Styles.Style().SelectedMenuEntry
		} else {
			style = m.config.Styles.Style().MenuEntry
		}
		if width < m.maxLabelWidth {
			style = style.PaddingRight(style.GetPaddingRight() + (m.maxLabelWidth - width))
		}
		labels = append(labels, style.Render(e.Label))
	}
	return uv.NewStyledString(m.config.Styles.Style().Border.Render(lipgloss.JoinVertical(lipgloss.Left, labels...)))
}
