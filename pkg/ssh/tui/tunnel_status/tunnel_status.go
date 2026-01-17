package tunnel_status

import (
	"container/ring"
	"fmt"

	"charm.land/bubbles/v2/key"
	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"
	"github.com/charmbracelet/colorprofile"
	uv "github.com/charmbracelet/ultraviolet"
	"github.com/charmbracelet/x/ansi"

	extensions_ssh "github.com/pomerium/envoy-custom/api/extensions/filters/network/ssh"
	"github.com/pomerium/pomerium/pkg/ssh/models"
	"github.com/pomerium/pomerium/pkg/ssh/tui/core"
	"github.com/pomerium/pomerium/pkg/ssh/tui/core/layout"
	"github.com/pomerium/pomerium/pkg/ssh/tui/preferences"
	"github.com/pomerium/pomerium/pkg/ssh/tui/style"
	"github.com/pomerium/pomerium/pkg/ssh/tui/tunnel_status/components"
	"github.com/pomerium/pomerium/pkg/ssh/tui/tunnel_status/messages"
	"github.com/pomerium/pomerium/pkg/ssh/tui/widgets/dialog"
	"github.com/pomerium/pomerium/pkg/ssh/tui/widgets/header"
	"github.com/pomerium/pomerium/pkg/ssh/tui/widgets/help"
	"github.com/pomerium/pomerium/pkg/ssh/tui/widgets/label"
	"github.com/pomerium/pomerium/pkg/ssh/tui/widgets/logviewer"
	"github.com/pomerium/pomerium/pkg/ssh/tui/widgets/menu"
)

const (
	prefMotdSeen = "motd.seen"
)

func prefComponentHidden(id string) string {
	return fmt.Sprintf("components.%s.hidden", id)
}

type KeyMap struct {
	FocusNext     key.Binding
	FocusPrev     key.Binding
	Quit          key.Binding
	showHidePanel key.Binding

	// runtime use
	focusedKeyMap help.KeyMap
	modalKeyMap   help.KeyMap
}

func (k *KeyMap) setFocusedKeyMap(km help.KeyMap) {
	k.focusedKeyMap = km
}

func (k *KeyMap) setModalKeyMap(km help.KeyMap) {
	k.modalKeyMap = km
}

// FullHelp implements help.KeyMap.
func (k *KeyMap) FullHelp() [][]key.Binding {
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
func (k *KeyMap) ShortHelp() []key.Binding {
	var fh []key.Binding
	if k.modalKeyMap != nil {
		return k.modalKeyMap.ShortHelp()
	} else if k.focusedKeyMap != nil {
		fh = k.focusedKeyMap.ShortHelp()
	}
	return append([]key.Binding{k.Quit, k.FocusNext, k.showHidePanel}, fh...)
}

type Model struct {
	config       Config
	themeManager style.ThemeManager
	prefs        preferences.Preferences
	termEnv      string

	headerModel      *header.Model
	headerWidget     core.Widget
	backgroundWidget core.Widget

	components *components.Group

	helpModel  *help.Model
	helpWidget core.Widget

	dialogModel  *dialog.Model
	dialogWidget core.Widget

	contextMenuModel  *menu.Model
	contextMenuWidget core.Widget

	mouseMode              tea.MouseMode
	ignoreNextMouseRelease bool
	noChangesInLastUpdate  bool

	grid    *layout.GridLayout
	profile colorprofile.Profile

	tabOrder              *ring.Ring
	lastWidth, lastHeight int
	lastView              *lipgloss.Canvas

	modalInterceptor       *messages.ModalInterceptor
	modalPreviousTheme     *style.Theme
	modalPreviousMouseMode *tea.MouseMode
}

var AppName string

func init() {
	if AppName == "" {
		AppName = "Pomerium"
	}
}

const (
	IDHeader     = "header"
	IDBackground = "background"
	IDHelp       = "help"
	IDMenu       = "menu"
	IDDialog     = "dialog"
)

func NewTunnelStatusModel(tm style.ThemeManager, prefs preferences.Preferences, config Config, cfr components.ComponentFactoryRegistry) *Model {
	m := &Model{
		config:       config,
		prefs:        prefs,
		themeManager: tm,
		components:   components.NewGroup(cfr, config.Components...),
		mouseMode:    tea.MouseModeCellMotion,
		headerModel: header.NewModel(header.Config{
			Options: header.Options{
				LeftAlignedSegments:  config.Header.LeftAlignedSegments(config.Styles),
				RightAlignedSegments: config.Header.RightAlignedSegments(config.Styles),
			},
		}),
		helpModel: help.NewModel(help.Config{
			Styles:  style.Bind(config.Styles, func(base *Styles) help.Styles { return base.Help }).SetUpdateEnabled(false),
			Options: help.DefaultOptions,
		}),
		contextMenuModel: menu.NewContextMenuModel(menu.Config{
			Styles: style.Bind(config.Styles, func(base *Styles) menu.Styles { return base.ContextMenu }),
		}),
		dialogModel: dialog.NewModel(dialog.Config{
			Styles: style.Bind(config.Styles, func(base *Styles) dialog.Styles { return base.Dialog }),
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
	m.dialogWidget = core.NewWidget(IDDialog, m.dialogModel)
	m.contextMenuWidget = core.NewWidget(IDMenu, m.contextMenuModel)

	m.config.KeyMap.showHidePanel = m.components.MnemonicBinding()
	m.helpWidget = core.NewWidget(IDHelp, m.helpModel)
	for component := range m.components.RowMajorOrder() {
		if preferences.GetOrDefault(m.prefs, prefComponentHidden(component.ID()), false) {
			component.SetHidden(true)
		}
	}

	m.tabOrder = m.buildTabOrder()
	for first := range m.components.RowMajorOrder() {
		m.config.KeyMap.setFocusedKeyMap(first.Model().KeyMap())
		first.Model().Focus()
		break
	}
	m.helpModel.DisplayedKeyMap = &m.config.KeyMap

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
	var cmds []tea.Cmd
	cmds = append(cmds, tea.Raw(ansi.RequestPrimaryDeviceAttributes))
	if m.config.ShowMotdOnStart {
		if !preferences.TestAndSetFlag(m.prefs, prefMotdSeen) {
			cmds = append(cmds, m.showMotd())
		}
	}
	return tea.Batch(cmds...)
}

func (m *Model) showMotd() tea.Cmd {
	return m.showDialog(dialog.Options{
		Contents: core.NewWidget("", label.NewModel(label.Config{
			Options: label.Options{
				Text:   m.config.MotdText,
				HAlign: lipgloss.Left,
				VAlign: lipgloss.Top,
			},
			Styles: style.Bind(m.config.Styles, func(base *Styles) label.Styles {
				return label.Styles{
					Normal: base.DialogText.Padding(4, 8, 4, 8),
				}
			}),
		})),
		Buttons: []dialog.ButtonConfig{
			{
				Label:   "Close",
				Default: true,
				OnClick: dialog.Close,
			},
		},
		ButtonsAlignment: lipgloss.Center,
		Closeable:        false,
		KeyMap:           dialog.DefaultKeyMap,
	})
}

func (m *Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	return m, m.update(msg)
}

func (m *Model) update(msg tea.Msg) tea.Cmd {
	m.noChangesInLastUpdate = false
	var cmds []tea.Cmd
	switch msg := msg.(type) {
	case tea.EnvMsg:
		if value, ok := msg.LookupEnv("TERM"); ok {
			m.termEnv = value
		}
	case tea.ColorProfileMsg:
		m.profile = msg.Profile
	case tea.WindowSizeMsg:
		m.lastWidth, m.lastHeight = msg.Width, msg.Height
		m.resize(msg.Width, msg.Height)
		return nil
	case messages.ModalAcquireMsg:
		return m.setModalInterceptor(msg.Interceptor)
	case messages.ModalReleaseMsg:
		m.ignoreNextMouseRelease = msg.IgnoreNextMouseRelease
		return m.resetModalInterceptor(msg.Interceptor)
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
				m.config.KeyMap.setFocusedKeyMap(m.tabOrder.Value.(core.Model).KeyMap())
			}
		case key.Matches(msg, m.config.KeyMap.FocusPrev):
			if m.tabOrder.Len() > 0 {
				cmds = append(cmds, m.tabOrder.Value.(core.Model).Blur())
				m.tabOrder = m.tabOrder.Prev()
				cmds = append(cmds, m.tabOrder.Value.(core.Model).Focus())
				m.config.KeyMap.setFocusedKeyMap(m.tabOrder.Value.(core.Model).KeyMap())
			}
		case key.Matches(msg, m.config.KeyMap.Quit):
			return tea.Quit
		case key.Matches(msg, m.components.MnemonicBinding()):
			if c, ok := m.components.LookupMnemonic(msg.Key().String()); ok {
				c.SetHidden(!c.Hidden())
				m.prefs.Put(prefComponentHidden(c.ID()), c.Hidden())
				cmds = append(cmds, c.Model().Blur())
			}
			m.config.KeyMap.setFocusedKeyMap(nil)
			m.tabOrder = m.buildTabOrder()

			if m.tabOrder.Len() > 0 {
				for r := m.tabOrder.Next(); r != m.tabOrder; r = r.Next() {
					if r.Value.(core.Model).Focused() {
						m.tabOrder = r
						break
					}
				}
				cmds = append(cmds, m.tabOrder.Value.(core.Model).Focus())
				m.config.KeyMap.setFocusedKeyMap(m.tabOrder.Value.(core.Model).KeyMap())
			}
			m.grid = m.buildGridLayout()
			m.resize(m.lastWidth, m.lastHeight)
		}
	case tea.MouseMsg:
		if m.lastView == nil {
			return nil
		}

		if m.modalInterceptor != nil {
			return m.modalInterceptor.Update(msg)
		}

		id := m.lastView.Hit(msg.Mouse().X, msg.Mouse().Y)
		if id == "" {
			return nil
		}

		if m.ignoreNextMouseRelease {
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
		case IDDialog:
			return m.dialogModel.Update(msg)
		case IDHeader:
			return m.headerModel.Update(msg)
		case IDHelp:
			return m.helpModel.Update(msg)
		default:
			if c, ok := m.components.LookupID(id); ok {
				model := c.Model()
				switch msg := msg.(type) {
				case tea.MouseMotionMsg:
					// mouse motion should not affect panel focus
					if model.Focused() {
						return model.Update(msg)
					}
				default:
					if !model.Focused() {
						return tea.Sequence(m.setFocus(model), model.Update(msg))
					}
					return model.Update(msg)
				}
			}
		}
	case models.Session:
		m.headerModel.UpdateSession(&msg)
		return nil
	case menu.ShowMsg:
		return m.showContextMenu(msg)
	case dialog.ShowMsg:
		return m.showDialog(msg.Options)
	case *extensions_ssh.Diagnostic:
		logMsgs := []string{}
		switch msg.Severity {
		case extensions_ssh.Diagnostic_Info:
			logMsgs = append(logMsgs, msg.GetMessage())
		case extensions_ssh.Diagnostic_Warning:
			logMsgs = append(logMsgs, m.config.Styles.Style().Logs.Warning.Render("warning: "+msg.GetMessage()))
			for _, hint := range msg.Hints {
				logMsgs = append(logMsgs, m.config.Styles.Style().Logs.Warning.Faint(true).Render("   hint: "+hint))
			}
		case extensions_ssh.Diagnostic_Error:
			logMsgs = append(logMsgs, m.config.Styles.Style().Logs.Error.Render("error: "+msg.GetMessage()))
			for _, hint := range msg.Hints {
				logMsgs = append(logMsgs, m.config.Styles.Style().Logs.Error.Faint(true).Render(" hint: "+hint))
			}
		}
		return logviewer.AddLogs(logMsgs...)
	}

	cmds = append(cmds,
		m.helpModel.Update(msg),
		m.headerModel.Update(msg),
		m.dialogModel.Update(msg),
		m.contextMenuModel.Update(msg),
	)
	for comp := range m.components.RowMajorOrder() {
		cmds = append(cmds, comp.Model().Update(msg))
	}
	return tea.Batch(cmds...)
}

func (m *Model) setModalInterceptor(interceptor *messages.ModalInterceptor) tea.Cmd {
	if interceptor == nil {
		panic("bug: setModalInterceptor must be passed a non-nil argument")
	}
	if m.modalInterceptor != nil {
		_ = m.resetModalInterceptor(m.modalInterceptor)
	}
	m.modalInterceptor = interceptor
	var cmds []tea.Cmd
	if interceptor.KeyMap != nil {
		m.config.KeyMap.setModalKeyMap(interceptor.KeyMap)
	}
	if interceptor.MouseModeOverride != nil {
		prevMode := m.mouseMode
		m.modalPreviousMouseMode = &prevMode
		m.mouseMode = *interceptor.MouseModeOverride
	}
	if interceptor.Scrim {
		colors := m.themeManager.ActiveTheme().Colors
		colors.Accent1.Normal = ansi.BrightBlack
		colors.Accent2.Normal = ansi.BrightBlack
		colors.Accent3.Normal = ansi.BrightBlack
		colors.Accent4.Normal = ansi.BrightBlack
		colors.CardBorderForeground = ansi.BrightBlack
		newTheme := style.NewTheme(colors, style.WithDefaultStyle(lipgloss.NewStyle().Faint(true)))

		m.modalPreviousTheme = m.themeManager.SetTheme(newTheme)
		cmds = append(cmds, m.forceRedraw)
	}

	return tea.Batch(cmds...)
}

func (m *Model) resetModalInterceptor(interceptor *messages.ModalInterceptor) tea.Cmd {
	if interceptor == nil {
		panic("bug: resetModalInterceptor must be passed a non-nil argument")
	}
	var cmds []tea.Cmd
	if m.modalInterceptor != nil && m.modalInterceptor == interceptor {
		m.modalInterceptor = nil
		m.config.KeyMap.setModalKeyMap(nil)

		if m.modalPreviousTheme != nil {
			prev := m.modalPreviousTheme
			m.modalPreviousTheme = nil
			m.themeManager.SetTheme(prev)
		}
		if m.modalPreviousMouseMode != nil {
			m.mouseMode = *m.modalPreviousMouseMode
			m.modalPreviousMouseMode = nil
		}
		if interceptor.Scrim {
			cmds = append(cmds, m.forceRedraw)
		}
	}
	return tea.Batch(cmds...)
}

func (m *Model) forceRedraw() tea.Msg {
	return tea.WindowSizeMsg{Width: m.lastWidth, Height: m.lastHeight}
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

func (m *Model) showContextMenu(msg menu.ShowMsg) tea.Cmd {
	if m.contextMenuModel.Focused() {
		return nil
	}
	m.contextMenuModel.Reset(msg.Options)
	width, height := m.contextMenuModel.SizeHint()
	x, y := msg.Options.Anchor.X, msg.Options.Anchor.Y+1
	if x+width >= m.lastWidth {
		// shift left
		x -= (x + width) - m.lastWidth
	}
	if y+height >= m.lastHeight {
		// shift up
		y += (y + height) - m.lastHeight
	}
	m.contextMenuWidget.SetBounds(uv.Rect(x, y, width, height))
	return m.contextMenuModel.Focus()
}

func (m *Model) showDialog(options dialog.Options) tea.Cmd {
	if m.dialogModel.Focused() {
		return nil
	}
	m.dialogModel.Reset(options)
	m.resizeDialog(m.lastWidth, m.lastHeight)
	return m.dialogModel.Focus()
}

func (m *Model) resizeDialog(width, height int) {
	var w, h int
	if width > 0 && height > 0 {
		w, h = m.dialogModel.SizeHint()
	}
	m.dialogWidget.SetBounds(uv.CenterRect(uv.Rect(0, 0, width, height), min(w, width), min(h, height)))
}

func (m *Model) setFocus(toFocus core.Model) tea.Cmd {
	if toFocus.Focused() || m.tabOrder == nil {
		return nil
	}
	if m.tabOrder.Value.(core.Model) == toFocus {
		cmd := toFocus.Focus()
		m.config.KeyMap.setFocusedKeyMap(toFocus.KeyMap())
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
	m.config.KeyMap.setFocusedKeyMap(m.tabOrder.Value.(core.Model).KeyMap())
	return tea.Batch(cmds...)
}

func (m *Model) resize(width int, height int) {
	m.grid.Resize(width, height)
	if m.dialogModel.Focused() {
		m.resizeDialog(width, height)
	}
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
		if m.contextMenuModel.Focused() {
			layers = append(layers, m.contextMenuWidget.Layer().Z(99))
		}
		if m.dialogModel.Focused() {
			layers = append(layers, m.dialogWidget.Layer().Z(100))
		}
		canvas.AddLayers(layers...)

		m.lastView = canvas
	}
	return tea.View{
		ContentDrawable: m.lastView,
		BackgroundColor: m.config.Styles.Style().BackgroundColor,
		AltScreen:       true,
		MouseMode:       m.mouseMode,
	}
}
