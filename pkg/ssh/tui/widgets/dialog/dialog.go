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
	"github.com/pomerium/pomerium/pkg/ssh/tui/tunnel/messages"
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

	options         Options
	buttons         []core.Widget
	grid            *layout.GridLayout
	width, height   int
	canvas          *lipgloss.Canvas
	lastRenderOrder core.RenderOrder
	interceptor     *messages.ModalInterceptor
	focused         bool
	focusedButton   int

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
	core.ApplyKeyMapDefaults(&options.KeyMap, DefaultKeyMap)
	m.options = options
	m.buttons = []core.Widget{}
	m.focused = false
	m.focusedButton = -1

	m.options.KeyMap.Close.SetEnabled(!m.options.ActionRequired)
	m.options.KeyMap.Next.SetEnabled(len(m.options.Buttons) > 1)
	m.options.KeyMap.Prev.SetEnabled(len(m.options.Buttons) > 1)

	var buttonCells []layout.RowCell
	styles := m.config.Styles.Style()
	for i, bc := range m.options.Buttons {
		btn := core.NewWidget(strconv.Itoa(i), label.NewModel(label.Config{
			Styles: style.Bind(m.config.Styles, func(base *Styles, _ style.NewStyleFunc) label.Styles {
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
				return lipgloss.Width(bc.Label) + styles.Button.GetHorizontalFrameSize()
			},
			Widget: btn,
		})
		if bc.Default {
			for _, prev := range m.buttons[:i] {
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
	m.canvas = lipgloss.NewCanvas(0, 0)
	// m.canvas.AddLayers(m.options.Contents.Layer())
	// for _, btn := range m.buttons {
	// 	m.canvas.AddLayers(btn.Layer())
	// }
	m.interceptor = &messages.ModalInterceptor{
		Update: m.Update,
		KeyMap: m.options.KeyMap,
		Scrim:  true,
	}
}

func (m *Model) Update(msg tea.Msg) core.Status {
	if !m.focused {
		return core.NilCmd
	}
	switch msg := msg.(type) {
	case tea.KeyPressMsg:
		switch {
		case key.Matches(msg.Key(), m.options.KeyMap.Close):
			return core.Cmd(m.Blur())
		case key.Matches(msg.Key(), m.options.KeyMap.Next):
			m.focusNextButton()
			return core.NilCmd
		case key.Matches(msg.Key(), m.options.KeyMap.Prev):
			m.focusPrevButton()
			return core.NilCmd
		case key.Matches(msg.Key(), m.options.KeyMap.Select):
			return core.Cmd(m.selectCurrentButton())
		}
	case tea.MouseMsg:
		pos := msg.Mouse()
		styles := m.config.Styles.Style()
		// offset by (1, 1) since the border is not part of the canvas
		offsetX := styles.Dialog.GetBorderLeftSize()
		offsetY := styles.Dialog.GetBorderTopSize()
		local, inBounds := m.Parent().TranslateGlobalToLocalPos(uv.Pos(pos.X-offsetX, pos.Y-offsetY))
		if !inBounds {
			switch msg.(type) {
			case tea.MouseClickMsg:
				if !m.options.ActionRequired {
					return core.Cmd(m.hide(true))
				}
				return core.Cmd(m.flashBorder())
			case tea.MouseReleaseMsg:
				// Do nothing here. The initial click would have originated from
				// within the dialog bounds
				return core.NilCmd
			}
			return core.SkipNextRender
		}
		hit := m.lastRenderOrder.HitTest(local.X, local.Y)
		if !hit.Empty() {
			index, err := strconv.Atoi(hit.ID)
			if err == nil && index < len(m.buttons) {
				m.focusButton(index)
				switch msg.(type) {
				case tea.MouseClickMsg:
				case tea.MouseReleaseMsg:
					return core.Cmd(m.selectCurrentButton())
				}
			}
		}
	case FlashBorderMsg:
		if msg.context.Err() != nil {
			return core.NilCmd
		}
		m.borderFlashing = msg.flashOn
		return core.Cmd(msg.next())
	}
	return core.NilCmd
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
	styles := m.config.Styles.Style()
	if len(m.buttons) > 0 {
		h++
		buttonsWidth := 0
		for _, btn := range m.options.Buttons {
			buttonsWidth += lipgloss.Width(btn.Label)
			buttonsWidth += styles.Button.GetHorizontalFrameSize()
		}
		if m.options.ButtonsAlignment == lipgloss.Center {
			// If the buttons don't center evenly, increase the total width by 1
			if (buttonsWidth % 2) != (w % 2) {
				parityAdjust = 1
			}
		}
		w = max(w, buttonsWidth)
	}
	w += styles.Dialog.GetHorizontalFrameSize() + parityAdjust
	h += styles.Dialog.GetVerticalFrameSize()
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
		m.focusButton(m.focusedButton - 1)
	} else {
		m.focusButton(len(m.buttons) - 1)
	}
}

func (m *Model) focusNextButton() {
	m.focusButton((m.focusedButton + 1) % len(m.buttons))
}

func (m *Model) focusButton(idx int) {
	if m.focusedButton < len(m.buttons) {
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
	styles := m.config.Styles.Style()
	m.width = max(0, w-styles.Dialog.GetHorizontalFrameSize())
	m.height = max(0, h-styles.Dialog.GetVerticalFrameSize())
	m.grid.Resize(m.width, m.height)
}

func (m *Model) View() uv.Drawable {
	styles := m.config.Styles.Style()
	style := styles.Dialog
	if m.borderFlashing {
		style = styles.DialogFlash
	}

	renderOrder := core.RenderOrder{}
	m.canvas.Resize(m.width, m.height)
	m.canvas.Clear()
	render := func(w core.Widget) {
		bounds := w.Bounds()
		w.Draw(m.canvas, bounds)
		renderOrder = append(renderOrder, core.RenderInfo{ID: w.ID(), Bounds: bounds})
	}
	render(m.options.Contents)
	for _, btn := range m.buttons {
		render(btn)
	}
	m.lastRenderOrder = renderOrder
	return uv.NewStyledString(style.Render(m.canvas.Render()))
}
