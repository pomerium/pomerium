package dialog

import (
	"fmt"

	"charm.land/bubbles/v2/key"
	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"
	uv "github.com/charmbracelet/ultraviolet"
	"github.com/pomerium/pomerium/pkg/ssh/tui/core"
	"github.com/pomerium/pomerium/pkg/ssh/tui/core/layout"
	"github.com/pomerium/pomerium/pkg/ssh/tui/style"
	"github.com/pomerium/pomerium/pkg/ssh/tui/tunnel_status/messages"
	"github.com/pomerium/pomerium/pkg/ssh/tui/widgets/help"
	"github.com/pomerium/pomerium/pkg/ssh/tui/widgets/label"
)

type KeyMap struct {
	Close  key.Binding
	Next   key.Binding
	Prev   key.Binding
	Select key.Binding
}

// ShortHelp implements help.KeyMap.
func (k KeyMap) ShortHelp() []key.Binding {
	return []key.Binding{k.Close, k.Next, k.Prev, k.Select}
}

// FullHelp implements help.KeyMap.
func (k KeyMap) FullHelp() [][]key.Binding {
	return [][]key.Binding{{k.Close, k.Next, k.Prev, k.Select}}
}

type Model struct {
	core.BaseModel
	config        Config
	buttons       []core.Widget
	grid          *layout.GridLayout
	canvas        *lipgloss.Canvas
	interceptor   *messages.ModalInterceptor
	focused       bool
	focusedButton int
}

func NewModel(config Config) *Model {
	m := &Model{
		config:        config,
		focusedButton: -1,
	}
	if !config.Closeable {
		config.KeyMap.Close.SetEnabled(false)
	}
	var buttonCells []layout.RowCell
	for i, bc := range config.Buttons {
		btn := core.NewWidget(fmt.Sprintf("button%d", i), label.NewModel(label.Config{
			Styles: style.Bind(config.Styles, func(base *Styles) label.Styles {
				return label.Styles{
					Normal:  base.Button,
					Focused: base.SelectedButton,
				}
			}),
			Options: label.Options{
				Text:   bc.Label,
				HAlign: lipgloss.Center,
				VAlign: lipgloss.Center,
			},
		}))
		buttonCells = append(buttonCells, layout.RowCell{
			Title: bc.Label,
			SizeFunc: func() int {
				return lipgloss.Width(bc.Label) + config.Styles.Style().Button.GetHorizontalFrameSize()
			},
			Widget: btn,
		})
		if bc.Default {
			for _, prev := range m.buttons {
				prev.Model().Blur()
			}
			btn.Model().Focus()
			m.focusedButton = i
		}
		m.buttons = append(m.buttons, btn)
	}
	switch config.ButtonsAlignment {
	case lipgloss.Left:
		buttonCells = append([]layout.RowCell{{Title: "SpacerL", Size: -10}}, buttonCells...)
	case lipgloss.Right:
		buttonCells = append(buttonCells, layout.RowCell{Title: "SpacerR", Size: -10})
	default:
		fallthrough
	case lipgloss.Center:
		buttonCells = append(append([]layout.RowCell{{Title: "SpacerL", Size: -10}}, buttonCells...), layout.RowCell{Title: "SpacerR", Size: -10})
	}

	rows := []layout.Row{
		{
			Height: -1,
			Columns: []layout.RowCell{
				{
					Title:  "Message",
					Size:   -1,
					Widget: m.config.Contents,
				},
			},
		},
		{
			Height:  1,
			Columns: buttonCells,
		},
	}
	grid := layout.NewGridLayout(rows)
	m.grid = grid
	m.canvas = lipgloss.NewCanvas()
	m.canvas.AddLayers(m.config.Contents.Layer())
	for _, btn := range m.buttons {
		m.canvas.AddLayers(btn.Layer())
	}
	m.interceptor = &messages.ModalInterceptor{
		Update: m.Update,
		KeyMap: m.config.KeyMap,
		Scrim:  true,
	}
	return m
}

func (m *Model) Update(msg tea.Msg) tea.Cmd {
	switch msg := msg.(type) {
	case tea.KeyPressMsg:
		switch {
		case key.Matches(msg.Key(), m.config.KeyMap.Close):
			return m.Blur()
		case key.Matches(msg.Key(), m.config.KeyMap.Next):
			m.focusNextButton()
			return nil
		case key.Matches(msg.Key(), m.config.KeyMap.Prev):
			m.focusPrevButton()
			return nil
		case key.Matches(msg.Key(), m.config.KeyMap.Select):
			return m.selectCurrentButton()
		}
	case tea.MouseMotionMsg:
	case tea.MouseClickMsg:
	case tea.MouseReleaseMsg:

	}
	return nil
}

func (m *Model) SizeHint() (int, int) {
	w, h := m.config.Contents.Model().SizeHint()
	parityAdjust := 0
	if len(m.buttons) > 0 {
		h++
		buttonsWidth := 0
		for _, btn := range m.config.Buttons {
			buttonsWidth += lipgloss.Width(btn.Label)
			buttonsWidth += m.config.Styles.Style().Button.GetHorizontalFrameSize()
		}
		if m.config.ButtonsAlignment == lipgloss.Center {
			// If the buttons don't center evenly, increase the total width by 1
			if (buttonsWidth % 2) != (w % 2) {
				parityAdjust = 1
			}
		}
		w = max(w, buttonsWidth)
	}
	w += m.config.Styles.Style().Dialog.GetHorizontalFrameSize() + parityAdjust
	h += m.config.Styles.Style().Dialog.GetVerticalFrameSize()
	return w, h
}

func (m *Model) selectCurrentButton() tea.Cmd {
	if m.focusedButton != -1 {
		return tea.Batch(m.Blur(), m.config.Buttons[m.focusedButton].OnClick())
	}
	return nil
}

func (m *Model) focusPrevButton() {
	if m.focusedButton > 0 {
		m.buttons[m.focusedButton].Model().Blur()
		m.focusedButton--
		m.buttons[m.focusedButton].Model().Focus()
	}
}

func (m *Model) focusNextButton() {
	if m.focusedButton < len(m.buttons)-1 {
		m.buttons[m.focusedButton].Model().Blur()
		m.focusedButton++
		m.buttons[m.focusedButton].Model().Focus()
	}
}

func (m *Model) Blur() tea.Cmd {
	if !m.focused {
		return nil
	}
	m.focused = false
	m.config.Styles.SetEnabled(true)
	return messages.ModalRelease(m.interceptor)
}

func (m *Model) Focus() tea.Cmd {
	if m.focused {
		return nil
	}
	m.focused = true
	m.config.Styles.SetEnabled(false)
	return messages.ModalAcquire(m.interceptor)
}
func (m *Model) Focused() bool { return m.focused }
func (m *Model) KeyMap() help.KeyMap {
	return m.config.KeyMap
}

func (m *Model) OnResized(w, h int) {
	m.grid.Resize(w-m.config.Styles.Style().Dialog.GetHorizontalFrameSize(),
		h-m.config.Styles.Style().Dialog.GetVerticalFrameSize())
}

func (m *Model) View() uv.Drawable {
	return uv.NewStyledString(m.config.Styles.Style().Dialog.Render(m.canvas.Render()))
}
