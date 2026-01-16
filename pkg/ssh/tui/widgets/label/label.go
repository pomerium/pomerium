package label

import (
	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"
	uv "github.com/charmbracelet/ultraviolet"

	"github.com/pomerium/pomerium/pkg/ssh/tui/core"
)

type Model struct {
	core.BaseModel
	config        Config
	width, height int
	focused       bool
}

func NewModel(config Config) *Model {
	return &Model{
		config: config,
	}
}

func (m *Model) OnResized(maxWidth, maxHeight int) {
	m.width = maxWidth
	m.height = maxHeight
}

func (m *Model) Update(msg tea.Msg) tea.Cmd {
	return nil
}

func (m *Model) currentStyle() lipgloss.Style {
	if m.config.Styles == nil {
		return lipgloss.NewStyle()
	}
	if m.focused {
		return m.config.Styles.Style().Focused
	}
	return m.config.Styles.Style().Normal
}

func (m *Model) View() uv.Drawable {
	style := m.currentStyle()
	return uv.NewStyledString(
		style.Render(
			lipgloss.Place(
				m.width-style.GetHorizontalFrameSize(),
				m.height-style.GetVerticalFrameSize(),
				m.config.HAlign, m.config.VAlign,
				m.config.Text)))
}

func (m *Model) KeyMap() core.KeyMap { return nil }
func (m *Model) SizeHint() (int, int) {
	w, h := lipgloss.Size(m.config.Text)
	fw, fh := m.config.Styles.Style().Normal.GetFrameSize()
	return w + fw, h + fh
}
func (m *Model) Focused() bool { return m.focused }
func (m *Model) Focus() tea.Cmd {
	m.focused = true
	return nil
}

func (m *Model) Blur() tea.Cmd {
	m.focused = false
	return nil
}
