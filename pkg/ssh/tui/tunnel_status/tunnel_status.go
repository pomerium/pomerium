package tunnel_status

import (
	"container/ring"
	"fmt"

	"charm.land/bubbles/v2/key"
	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"
	"github.com/charmbracelet/colorprofile"
	uv "github.com/charmbracelet/ultraviolet"

	extensions_ssh "github.com/pomerium/envoy-custom/api/extensions/filters/network/ssh"
	"github.com/pomerium/pomerium/pkg/ssh/models"
	"github.com/pomerium/pomerium/pkg/ssh/tui/core"
	"github.com/pomerium/pomerium/pkg/ssh/tui/core/layout"
	"github.com/pomerium/pomerium/pkg/ssh/tui/tunnel_status/common"
	"github.com/pomerium/pomerium/pkg/ssh/tui/tunnel_status/components"
	"github.com/pomerium/pomerium/pkg/ssh/tui/widgets/header"
	"github.com/pomerium/pomerium/pkg/ssh/tui/widgets/help"
	"github.com/pomerium/pomerium/pkg/ssh/tui/widgets/label"
	"github.com/pomerium/pomerium/pkg/ssh/tui/widgets/logviewer"
	"github.com/pomerium/pomerium/pkg/ssh/tui/widgets/menu"
)

type KeyMap struct {
	FocusNext     key.Binding
	FocusPrev     key.Binding
	Quit          key.Binding
	showHidePanel key.Binding

	// runtime use
	focusedKeyMap help.KeyMap
	modalKeyMap   help.KeyMap
}

// FullHelp implements help.KeyMap.
func (k KeyMap) FullHelp() [][]key.Binding {
	var fh [][]key.Binding
	if k.modalKeyMap != nil {
		return k.modalKeyMap.FullHelp()
	} else if k.focusedKeyMap != nil {
		fh = k.focusedKeyMap.FullHelp()
	} else {
		fh = append(fh, []key.Binding{})
	}
	fh[0] = append([]key.Binding{k.FocusNext, k.FocusPrev}, fh[0]...)
	return fh
}

// ShortHelp implements help.KeyMap.
func (k KeyMap) ShortHelp() []key.Binding {
	var fh []key.Binding
	if k.modalKeyMap != nil {
		return k.modalKeyMap.ShortHelp()
	} else if k.focusedKeyMap != nil {
		fh = k.focusedKeyMap.ShortHelp()
	}
	return append([]key.Binding{k.Quit, k.FocusNext, k.showHidePanel}, fh...)
}

type Model struct {
	config Config

	headerModel      *header.Model
	headerWidget     core.Widget
	backgroundWidget core.Widget

	components *components.Group

	helpModel  *help.Model
	helpWidget core.Widget

	contextMenuModel       *menu.Model
	contextMenuWidget      core.Widget
	contextMenuAnchor      *uv.Position
	contextMenuInterceptor *common.ModalInterceptor

	mouseMode              tea.MouseMode
	ignoreNextMouseRelease bool
	noChangesInLastUpdate  bool

	grid    *layout.GridLayout
	profile colorprofile.Profile

	tabOrder              *ring.Ring
	lastWidth, lastHeight int
	lastView              *lipgloss.Canvas

	modalInterceptor *common.ModalInterceptor
}

var AppName string

func init() {
	if AppName == "" {
		AppName = "Pomerium"
	}
}

const (
	IDHeader     = "Header"
	IDBackground = "Background"
	IDHelp       = "Help"
	IDMenu       = "Menu"
)

func NewTunnelStatusModel(config Config, cfr components.ComponentFactoryRegistry) *Model {
	m := &Model{
		config:     config,
		components: components.NewGroup(cfr, config.Components...),
		mouseMode:  tea.MouseModeCellMotion,
		headerModel: header.NewModel(header.Config{
			Options: header.Options{
				LeftAlignedSegments:  config.Header.LeftAlignedSegments(config.Styles.HeaderSegments),
				RightAlignedSegments: config.Header.RightAlignedSegments(config.Styles.HeaderSegments),
			},
		}),
		helpModel: help.NewModel(help.Config{
			Styles:  config.Styles.Help,
			Options: help.DefaultOptions,
		}),
		contextMenuModel: menu.NewContextMenuModel(menu.Config{
			Styles: config.Styles.ContextMenu,
			Options: menu.Options{
				KeyMap: menu.DefaultKeyMap,
			},
		}),
	}

	m.headerWidget = core.NewWidget(IDHeader, m.headerModel)
	m.backgroundWidget = core.NewWidget(IDBackground, label.NewModel(label.Config{
		Options: label.Options{
			Text: fmt.Sprintf("Press %s to %s",
				m.components.MnemonicBinding().Help().Key,
				m.components.MnemonicBinding().Help().Desc),
			HAlign: lipgloss.Center,
			VAlign: lipgloss.Center,
		},
	}))

	m.config.KeyMap.showHidePanel = m.components.MnemonicBinding()
	m.helpWidget = core.NewWidget(IDHelp, m.helpModel)

	m.tabOrder = m.buildTabOrder()
	for first := range m.components.RowMajorOrder() {
		m.config.KeyMap.focusedKeyMap = first.Model().KeyMap()
		first.Model().Focus()
		break
	}
	m.helpModel.DisplayedKeyMap = m.config.KeyMap

	m.grid = m.buildGridLayout()
	return m
}

func (m *Model) buildGridLayout() *layout.GridLayout {
	// Note: Title fields here are unused, but they are set to widget IDs for
	// ease of debugging
	rows := []layout.Row{}
	rows = append(rows, layout.Row{
		Height:  1,
		Columns: []layout.RowCell{{Title: IDHeader, Size: -1, Widget: m.headerWidget}},
	})
	components := m.components.ToLayoutRows()
	rows = append(rows, components...)
	if len(components) == 0 {
		rows = append(rows, layout.Row{
			Height:  -1,
			Columns: []layout.RowCell{{Title: IDBackground, Size: -1, Widget: m.backgroundWidget}},
		})
	}
	rows = append(rows, layout.Row{
		Height:  1,
		Columns: []layout.RowCell{{Title: IDHelp, Size: -1, Widget: m.helpWidget}},
	})

	return layout.NewGridLayout(rows)
}

func (m *Model) buildTabOrder() *ring.Ring {
	models := []core.Model{}
	for c := range m.components.RowMajorOrder() {
		if c.Hidden() {
			continue
		}
		models = append(models, c.Model())
	}
	r := ring.New(len(models))
	for _, m := range models {
		r.Value = m
		r = r.Next()
	}
	return r
}

func (m *Model) Init() tea.Cmd {
	return tea.Batch(
		tea.RequestBackgroundColor,
	)
}

func (m *Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	return m, m.update(msg)
}

func (m *Model) update(msg tea.Msg) tea.Cmd {
	m.noChangesInLastUpdate = false
	var cmds []tea.Cmd
	switch msg := msg.(type) {
	case tea.ColorProfileMsg:
		m.profile = msg.Profile
	case tea.WindowSizeMsg:
		m.lastWidth, m.lastHeight = msg.Width, msg.Height
		m.resize(msg.Width, msg.Height)
		return nil
	case common.ModalAcquireMsg:
		m.setModalInterceptor(msg.Interceptor)
		return nil
	case common.ModalReleaseMsg:
		m.resetModalInterceptor(msg.Interceptor)
		return nil
	case tea.KeyPressMsg:
		if m.shouldIntercept(msg) {
			return m.modalInterceptor.Update(msg)
		}
		switch {
		case key.Matches(msg, m.config.KeyMap.FocusNext):
			if m.tabOrder.Len() > 0 {
				cmds = append(cmds, m.tabOrder.Value.(core.Model).Blur())
				m.tabOrder = m.tabOrder.Next()
				cmds = append(cmds, m.tabOrder.Value.(core.Model).Focus())
				m.config.KeyMap.focusedKeyMap = m.tabOrder.Value.(core.Model).KeyMap()
			}
		case key.Matches(msg, m.config.KeyMap.FocusPrev):
			if m.tabOrder.Len() > 0 {
				cmds = append(cmds, m.tabOrder.Value.(core.Model).Blur())
				m.tabOrder = m.tabOrder.Prev()
				cmds = append(cmds, m.tabOrder.Value.(core.Model).Focus())
				m.config.KeyMap.focusedKeyMap = m.tabOrder.Value.(core.Model).KeyMap()
			}
		case key.Matches(msg, m.config.KeyMap.Quit):
			return tea.Quit
		case key.Matches(msg, m.components.MnemonicBinding()):
			if c, ok := m.components.LookupMnemonic(msg.Key().String()); ok {
				c.SetHidden(!c.Hidden())
				cmds = append(cmds, c.Model().Blur())
			}
			m.config.KeyMap.focusedKeyMap = nil
			m.tabOrder = m.buildTabOrder()

			if m.tabOrder.Len() > 0 {
				for r := m.tabOrder.Next(); r != m.tabOrder; r = r.Next() {
					if r.Value.(core.Model).Focused() {
						m.tabOrder = r
						break
					}
				}
				cmds = append(cmds, m.tabOrder.Value.(core.Model).Focus())
				m.config.KeyMap.focusedKeyMap = m.tabOrder.Value.(core.Model).KeyMap()
			}
			m.grid = m.buildGridLayout()
			m.resize(m.lastWidth, m.lastHeight)
		}
	case tea.MouseMsg:
		if m.lastView == nil {
			return nil
		}

		id := m.lastView.Hit(msg.Mouse().X, msg.Mouse().Y)
		if id == "" {
			return nil
		}
		if m.contextMenuWidget != nil && id != IDMenu {
			switch msg := msg.(type) {
			case tea.MouseClickMsg:
				// clicked outside the context menu
				m.hideContextMenu()
				m.ignoreNextMouseRelease = true
				return nil
			case tea.MouseReleaseMsg:
				// We may get a mouse release immediately in the same position as the
				// anchor.
				if uv.Pos(msg.X, msg.Y).In(uv.Rect(m.contextMenuAnchor.X-1, m.contextMenuAnchor.Y-1, 3, 2)) {
					return nil
				}
				m.contextMenuWidget = nil
				m.config.KeyMap.modalKeyMap = nil
			default:
				// ignore motion/scroll if they happen outside the context menu
				m.noChangesInLastUpdate = true
				return nil
			}
		} else if m.ignoreNextMouseRelease {
			switch msg.(type) {
			case tea.MouseReleaseMsg:
				m.ignoreNextMouseRelease = false
				return nil
			}
		}
		switch id {
		case "":
			return nil
		case IDMenu:
			return m.contextMenuModel.Update(msg)
		case IDHeader:
			return m.headerModel.Update(msg)
		case IDHelp:
			return m.helpModel.Update(msg)
		default:
			if c, ok := m.components.LookupID(id); ok {
				model := c.Model()
				return tea.Sequence(m.setFocus(model), model.Update(msg))
			}
		}
	case models.Session:
		m.headerModel.UpdateSession(&msg)
		return nil
	case menu.ShowMsg:
		m.showContextMenu(msg)
		return nil
	case menu.HideMsg:
		m.hideContextMenu()
		return nil
	case *extensions_ssh.Diagnostic:
		logMsgs := []string{}
		switch msg.Severity {
		case extensions_ssh.Diagnostic_Info:
			logMsgs = append(logMsgs, msg.GetMessage())
		case extensions_ssh.Diagnostic_Warning:
			logMsgs = append(logMsgs, m.config.Styles.Logs.Warning.Render("warning: "+msg.GetMessage()))
			for _, hint := range msg.Hints {
				logMsgs = append(logMsgs, m.config.Styles.Logs.Warning.Faint(true).Render("   hint: "+hint))
			}
		case extensions_ssh.Diagnostic_Error:
			logMsgs = append(logMsgs, m.config.Styles.Logs.Error.Render("error: "+msg.GetMessage()))
			for _, hint := range msg.Hints {
				logMsgs = append(logMsgs, m.config.Styles.Logs.Error.Faint(true).Render(" hint: "+hint))
			}
		}
		return logviewer.AddLogs(logMsgs...)
	}

	cmds = append(cmds,
		m.helpModel.Update(msg),
		m.headerModel.Update(msg),
	)
	for comp := range m.components.RowMajorOrder() {
		cmds = append(cmds, comp.Model().Update(msg))
	}
	return tea.Batch(cmds...)
}

func (m *Model) setModalInterceptor(interceptor *common.ModalInterceptor) {
	if interceptor == nil {
		panic("bug: setModalInterceptor must be passed a non-nil argument")
	}
	m.modalInterceptor = interceptor
	if interceptor.KeyMap != nil {
		m.config.KeyMap.modalKeyMap = interceptor.KeyMap
	}
}

func (m *Model) resetModalInterceptor(interceptor *common.ModalInterceptor) {
	if interceptor == nil {
		panic("bug: resetModalInterceptor must be passed a non-nil argument")
	}
	if m.modalInterceptor != nil && m.modalInterceptor == interceptor {
		m.modalInterceptor = nil
		m.config.KeyMap.modalKeyMap = nil
	}
}

func (m *Model) shouldIntercept(msg tea.Msg) bool {
	if m.modalInterceptor == nil {
		return false
	}
	switch msg.(type) {
	case tea.KeyMsg:
		return true
	default:
		return false
	}
}

func (m *Model) showContextMenu(msg menu.ShowMsg) {
	if len(msg.Entries) == 0 {
		return
	}
	m.contextMenuModel.Reset(msg.Entries)
	m.contextMenuAnchor = &msg.Anchor
	width, height := m.contextMenuModel.ContentDimensions()
	x, y := msg.Anchor.X, msg.Anchor.Y+1
	if x+width >= m.lastWidth {
		// shift left
		x -= (x + width) - m.lastWidth
	}
	if y+height >= m.lastHeight {
		// shift up
		y += (y + height) - m.lastHeight
	}
	m.contextMenuWidget = core.NewWidget(IDMenu, m.contextMenuModel)
	m.contextMenuWidget.SetBounds(uv.Rect(x, y, width, height))
	m.mouseMode = tea.MouseModeAllMotion
	m.contextMenuInterceptor = &common.ModalInterceptor{
		Update: m.contextMenuModel.Update,
		KeyMap: m.contextMenuModel.KeyMap(),
	}
	m.setModalInterceptor(m.contextMenuInterceptor)
}

func (m *Model) hideContextMenu() {
	m.contextMenuWidget = nil
	m.mouseMode = tea.MouseModeCellMotion
	if m.contextMenuInterceptor != nil {
		m.resetModalInterceptor(m.contextMenuInterceptor)
		m.contextMenuInterceptor = nil
	}
}

func (m *Model) setFocus(toFocus core.Model) tea.Cmd {
	if toFocus.Focused() || m.tabOrder == nil {
		return nil
	}
	if m.tabOrder.Value.(core.Model) == toFocus {
		cmd := toFocus.Focus()
		m.config.KeyMap.focusedKeyMap = toFocus.KeyMap()
		return cmd
	}
	var cmds []tea.Cmd
	cmds = append(cmds, m.tabOrder.Value.(core.Model).Blur())
	for r := m.tabOrder.Next(); r != m.tabOrder; r = r.Next() {
		if r.Value.(core.Model) == toFocus {
			m.tabOrder = r
			break
		}
	}
	cmds = append(cmds, m.tabOrder.Value.(core.Model).Focus())
	m.config.KeyMap.focusedKeyMap = m.tabOrder.Value.(core.Model).KeyMap()
	return tea.Batch(cmds...)
}

func (m *Model) resize(width int, height int) {
	m.grid.Resize(width, height)
}

func (m *Model) View() tea.View {
	if !m.noChangesInLastUpdate || m.lastView == nil {
		canvas := lipgloss.NewCanvas()
		layers := make([]*lipgloss.Layer, 0, 1+m.components.Size()+2)
		layers = append(layers, m.headerWidget.Layer().Z(2))
		for c := range m.components.RowMajorOrder() {
			if !c.Hidden() {
				layers = append(layers, c.Layer().Z(2))
			}
		}
		layers = append(layers, m.helpWidget.Layer().Z(2))
		layers = append(layers, m.backgroundWidget.Layer().Z(1))
		if m.contextMenuWidget != nil {
			layers = append(layers, m.contextMenuWidget.Layer().Z(99))
		}
		canvas.AddLayers(layers...)

		m.lastView = canvas
	}
	return tea.View{
		ContentDrawable: m.lastView,
		BackgroundColor: m.config.Styles.BackgroundColor,
		AltScreen:       true,
		MouseMode:       m.mouseMode,
	}
}
