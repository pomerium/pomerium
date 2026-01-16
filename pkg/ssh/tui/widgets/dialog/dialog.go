package dialog

import (
	"context"
	"strconv"
	"time"

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
	config Config

	options       Options
	buttons       []core.Widget
	grid          *layout.GridLayout
	canvas        *lipgloss.Canvas
	interceptor   *messages.ModalInterceptor
	focused       bool
	focusedButton int

	borderFlashing       bool
	cancelBorderFlashing context.CancelFunc
}

func NewModel(config Config) *Model {
	m := &Model{
		config: config,
	}
	return m
}

func (m *Model) Reset(options Options) {
	m.options = options
	m.buttons = []core.Widget{}
	m.focused = false
	m.focusedButton = -1

	m.options.KeyMap.Close.SetEnabled(m.options.Closeable)
	m.options.KeyMap.Next.SetEnabled(len(m.options.Buttons) > 1)
	m.options.KeyMap.Prev.SetEnabled(len(m.options.Buttons) > 1)

	var buttonCells []layout.RowCell
	for i, bc := range m.options.Buttons {
		btn := core.NewWidget(strconv.Itoa(i), label.NewModel(label.Config{
			Styles: style.Bind(m.config.Styles, func(base *Styles) label.Styles {
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
				return lipgloss.Width(bc.Label) + m.config.Styles.Style().Button.GetHorizontalFrameSize()
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
	switch m.options.ButtonsAlignment {
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
					Widget: m.options.Contents,
				},
			},
		},
		{
			Height:  1,
			Columns: buttonCells,
		},
	}
	m.grid = layout.NewGridLayout(rows)
	m.canvas = lipgloss.NewCanvas()
	m.canvas.AddLayers(m.options.Contents.Layer())
	for _, btn := range m.buttons {
		m.canvas.AddLayers(btn.Layer())
	}
	m.interceptor = &messages.ModalInterceptor{
		Update: m.Update,
		KeyMap: m.options.KeyMap,
		Scrim:  true,
	}
}

func (m *Model) Update(msg tea.Msg) tea.Cmd {
	if !m.focused {
		return nil
	}
	switch msg := msg.(type) {
	case tea.KeyPressMsg:
		switch {
		case key.Matches(msg.Key(), m.options.KeyMap.Close):
			return m.Blur()
		case key.Matches(msg.Key(), m.options.KeyMap.Next):
			m.focusNextButton()
			return nil
		case key.Matches(msg.Key(), m.options.KeyMap.Prev):
			m.focusPrevButton()
			return nil
		case key.Matches(msg.Key(), m.options.KeyMap.Select):
			return m.selectCurrentButton()
		}
	case tea.MouseMsg:
		pos := msg.Mouse()
		// offset by (1, 1) since the border is not part of the canvas
		offsetX := m.config.Styles.Style().Dialog.GetBorderLeftSize()
		offsetY := m.config.Styles.Style().Dialog.GetBorderTopSize()
		local, inBounds := m.Parent().TranslateGlobalToLocalPos(uv.Pos(pos.X-offsetX, pos.Y-offsetY))
		if !inBounds {
			switch msg.(type) {
			case tea.MouseClickMsg:
				if m.options.Closeable {
					return m.hide(true)
				}
				return m.flashBorder()
			case tea.MouseReleaseMsg:
				// Do nothing here. The initial click would have originated from
				// within the dialog bounds
				return nil
			}
			return nil
		}
		id := m.canvas.Hit(local.X, local.Y)
		if id != "" {
			index, err := strconv.Atoi(id)
			if err == nil && index < len(m.buttons) {
				m.focusButton(index)
				switch msg.(type) {
				case tea.MouseClickMsg:
				case tea.MouseReleaseMsg:
					return m.selectCurrentButton()
				}
			}
		}
	case FlashBorderMsg:
		if msg.context.Err() != nil {
			return nil
		}
		m.borderFlashing = msg.flashOn
		return msg.next()
	}
	return nil
}

type FlashBorderMsg struct {
	flashOn   bool
	context   context.Context
	nextAfter time.Duration
	remaining int
}

func (f *FlashBorderMsg) next() tea.Cmd {
	return func() tea.Msg {
		remaining := f.remaining
		if !f.flashOn {
			remaining--
		}
		if remaining == 0 {
			return nil
		}
		select {
		case <-time.After(f.nextAfter):
		case <-f.context.Done():
			return nil
		}
		return FlashBorderMsg{
			flashOn:   !f.flashOn,
			context:   f.context,
			nextAfter: f.nextAfter,
			remaining: remaining,
		}
	}
}

func (m *Model) flashBorder() tea.Cmd {
	return func() tea.Msg {
		if m.cancelBorderFlashing != nil {
			m.cancelBorderFlashing()
		}
		ctx, ca := context.WithCancel(context.Background())
		m.cancelBorderFlashing = ca
		return FlashBorderMsg{
			flashOn:   true,
			context:   ctx,
			nextAfter: 100 * time.Millisecond,
			remaining: 2,
		}
	}
}

func (m *Model) SizeHint() (int, int) {
	w, h := m.options.Contents.Model().SizeHint()
	parityAdjust := 0
	if len(m.buttons) > 0 {
		h++
		buttonsWidth := 0
		for _, btn := range m.options.Buttons {
			buttonsWidth += lipgloss.Width(btn.Label)
			buttonsWidth += m.config.Styles.Style().Button.GetHorizontalFrameSize()
		}
		if m.options.ButtonsAlignment == lipgloss.Center {
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
		return tea.Batch(m.Blur(), m.options.Buttons[m.focusedButton].OnClick())
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

func (m *Model) focusButton(idx int) {
	if m.focusedButton < len(m.buttons)-1 {
		m.buttons[m.focusedButton].Model().Blur()
		m.focusedButton = idx
		m.buttons[m.focusedButton].Model().Focus()
	}
}

func (m *Model) Blur() tea.Cmd {
	return m.hide(false)
}

func (m *Model) hide(ignoreNextMouseRelease bool) tea.Cmd {
	if !m.focused {
		return nil
	}
	m.focused = false
	m.config.Styles.SetUpdateEnabled(true) // assumes scrim is always enabled
	return messages.ModalRelease(m.interceptor, ignoreNextMouseRelease)
}

func (m *Model) Focus() tea.Cmd {
	return m.show()
}

func (m *Model) show() tea.Cmd {
	if m.focused {
		return nil
	}
	m.focused = true
	m.config.Styles.SetUpdateEnabled(false)
	return messages.ModalAcquire(m.interceptor)
}

func (m *Model) Focused() bool { return m.focused }

func (m *Model) KeyMap() help.KeyMap {
	return m.options.KeyMap
}

func (m *Model) OnResized(w, h int) {
	m.grid.Resize(max(0, w-m.config.Styles.Style().Dialog.GetHorizontalFrameSize()),
		max(0, h-m.config.Styles.Style().Dialog.GetVerticalFrameSize()))
}

func (m *Model) View() uv.Drawable {
	style := m.config.Styles.Style().Dialog
	if m.borderFlashing {
		style = m.config.Styles.Style().DialogFlash
	}
	return uv.NewStyledString(style.Render(m.canvas.Render()))
}
