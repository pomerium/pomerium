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

func (m *Model) View() uv.Drawable {
	return uv.NewStyledString(
		lipgloss.Place(m.width, m.height, m.config.HAlign, m.config.VAlign,
			m.config.Styles.Foreground.Render(m.config.Text)))
}

func (m *Model) KeyMap() core.KeyMap    { return nil }
func (m *Model) SetFocused(bool) *Model { return m }
func (m *Model) Focused() bool          { return false }
func (m *Model) Focus()                 {}
func (m *Model) Blur()                  {}
