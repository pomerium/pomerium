package tui

import (
	"cmp"
	"container/ring"
	"context"
	"fmt"
	"image"
	"maps"
	"net"
	"slices"
	"strconv"
	"strings"
	"time"

	"charm.land/bubbles/v2/help"
	"charm.land/bubbles/v2/key"
	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"
	"github.com/charmbracelet/colorprofile"
	uv "github.com/charmbracelet/ultraviolet"
	"github.com/charmbracelet/x/ansi"

	extensions_ssh "github.com/pomerium/envoy-custom/api/extensions/filters/network/ssh"
	"github.com/pomerium/pomerium/internal/hashutil"
	"github.com/pomerium/pomerium/pkg/ssh/portforward"
	"github.com/pomerium/pomerium/pkg/ssh/tui/table"
)

type TunnelStatusProgram struct {
	*tea.Program
	portForwardEndpoints map[string]portforward.RoutePortForwardInfo
}

func NewTunnelStatusProgram(ctx context.Context, opts ...tea.ProgramOption) *TunnelStatusProgram {
	model := NewTunnelStatusModel()
	return &TunnelStatusProgram{
		Program: tea.NewProgram(model, append(opts,
			tea.WithContext(ctx),
			tea.WithoutSignalHandler(),
		)...),
		portForwardEndpoints: map[string]portforward.RoutePortForwardInfo{},
	}
}

// OnClusterEndpointsUpdated implements portforward.UpdateListener.
func (ts *TunnelStatusProgram) OnClusterEndpointsUpdated(added map[string]portforward.RoutePortForwardInfo, removed map[string]struct{}) {
	maps.Copy(ts.portForwardEndpoints, added)
	for k := range removed {
		delete(ts.portForwardEndpoints, k)
	}
	go ts.Send(maps.Clone(ts.portForwardEndpoints))
}

// OnPermissionsUpdated implements portforward.UpdateListener.
func (ts *TunnelStatusProgram) OnPermissionsUpdated(permissions []portforward.Permission) {
	go ts.Send(permissions)
}

// OnRoutesUpdated implements portforward.UpdateListener.
func (ts *TunnelStatusProgram) OnRoutesUpdated(routes []portforward.RouteInfo) {
	go ts.Send(routes)
}

type ChannelRow struct {
	ID          int32
	Hostname    string
	Path        string
	Status      string
	PeerAddress string
	Stats       *extensions_ssh.ChannelStats
	Diagnostics []*extensions_ssh.Diagnostic
}

func (cr *ChannelRow) ToRow() table.Row {
	cols := []string{
		strconv.FormatUint(uint64(cr.ID), 10), // Channel
		cr.Status,                             // Status
		cr.Hostname,                           // Hostname
		cr.Path,                               // Path
		cr.PeerAddress,                        // RemoteIP
	}

	if cr.Stats != nil {
		cols = append(cols,
			strconv.FormatUint(cr.Stats.RxBytesTotal, 10),
			strconv.FormatUint(cr.Stats.TxBytesTotal, 10),
		)
		if cr.Stats.StartTime != nil && cr.Stats.EndTime == nil {
			cols = append(cols, time.Since(cr.Stats.StartTime.AsTime()).Round(time.Millisecond).String())
		} else if cr.Stats.StartTime != nil && cr.Stats.EndTime != nil {
			cols = append(cols, cr.Stats.EndTime.AsTime().Sub(cr.Stats.StartTime.AsTime()).Round(time.Millisecond).String())
		}
	}
	return table.Row(cols)
}

type model interface {
	View() string
	Focused() bool
	Focus()
	Blur()
	KeyMap() help.KeyMap
}

type Widget[Model model] struct {
	Rect   uv.Rectangle
	Model  Model
	Hidden bool
}

type TableWidget struct {
	Widget[*TableModel]
	ColumnLayout DirectionalLayout
}

type LogsWidget struct {
	Widget[*LogViewer]
}

type HelpWidget struct {
	Widget[*HelpModel]
}

type HelpModel struct {
	help.Model
	DisplayedKeyMap *KeyMap
}

func (hm *HelpModel) View() string {
	return hm.Model.View(hm.DisplayedKeyMap)
}

func (hm *HelpModel) Focused() bool {
	return false
}

func (hm *HelpModel) Focus()              {}
func (hm *HelpModel) Blur()               {}
func (hm *HelpModel) KeyMap() help.KeyMap { return hm.DisplayedKeyMap }

type TableModel struct {
	table.Model
}

func (tm *TableModel) KeyMap() help.KeyMap {
	return tm.Model.KeyMap
}

func (w *Widget[Model]) ToLayer() *lipgloss.Layer {
	var l lipgloss.Layer
	l.SetContent(w.Model.View())
	return l.
		X(w.Rect.Min.X).
		Y(w.Rect.Min.Y).
		Width(w.Rect.Dx()).
		Height(w.Rect.Dy())
}

type KeyMap struct {
	FocusNext     key.Binding
	FocusPrev     key.Binding
	Quit          key.Binding
	ShowHidePanel key.Binding
	FocusedKeyMap help.KeyMap
}

// FullHelp implements help.KeyMap.
func (k KeyMap) FullHelp() [][]key.Binding {
	var fh [][]key.Binding
	if k.FocusedKeyMap != nil {
		fh = k.FocusedKeyMap.FullHelp()
	} else {
		fh = append(fh, []key.Binding{})
	}
	fh[0] = append([]key.Binding{k.FocusNext, k.FocusPrev}, fh[0]...)
	return fh
}

// ShortHelp implements help.KeyMap.
func (k KeyMap) ShortHelp() []key.Binding {
	var fh []key.Binding
	if k.FocusedKeyMap != nil {
		fh = k.FocusedKeyMap.ShortHelp()
	}
	return append([]key.Binding{k.Quit, k.FocusNext, k.ShowHidePanel}, fh...)
}

var _ help.KeyMap = KeyMap{}

type TunnelStatusModel struct {
	channels TableWidget
	routes   TableWidget
	perms    TableWidget
	logs     LogsWidget
	help     HelpWidget

	grid    *GridLayout
	profile colorprofile.Profile

	activeChannels       map[uint32]*ChannelRow
	activePortForwards   map[string]portforward.RoutePortForwardInfo
	permissionMatchCount map[uint64]int
	allRoutes            []portforward.RouteInfo
	permissions          []portforward.Permission

	keyMap *KeyMap

	tabOrder              *ring.Ring
	lastWidth, lastHeight int
	lastView              *lipgloss.Canvas
}

var border = lipgloss.Border{
	Top:    "─",
	Left:   "│",
	Right:  "│",
	Bottom: "─",

	TopRight:    "╮",
	TopLeft:     "╭",
	BottomRight: "╯",
	BottomLeft:  "╰",
}

func tableStyle(accentColor lipgloss.ANSIColor, titleLeft string, titleRight string) table.Styles {
	return table.Styles{
		Selected:         lipgloss.NewStyle().Bold(true).Background(lipgloss.ANSIColor(8)).Foreground(lipgloss.White),
		Header:           lipgloss.NewStyle().Bold(true).PaddingLeft(1),
		Cell:             lipgloss.NewStyle().PaddingLeft(1),
		Border:           border,
		Focused:          lipgloss.NewStyle().BorderForeground(accentColor),
		BorderTitleLeft:  titleLeft,
		BorderTitleRight: titleRight,
	}
}

const (
	channelsAccentColor    = lipgloss.ANSIColor(ansi.Red)
	permissionsAccentColor = lipgloss.ANSIColor(ansi.Yellow)
	routesAccentColor      = lipgloss.ANSIColor(ansi.Green)
	logsAccentColor        = lipgloss.ANSIColor(ansi.Blue)
)

func newTableModel(accentColor lipgloss.ANSIColor, titleLeft, titleRight string, opts ...table.Option) *TableModel {
	return &TableModel{
		Model: table.New(tableStyle(accentColor, titleLeft, titleRight), opts...),
	}
}

func NewTunnelStatusModel() *TunnelStatusModel {
	m := &TunnelStatusModel{
		channels: TableWidget{
			ColumnLayout: NewDirectionalLayout([]Cell{
				{Title: "Channel", Size: 7 + 1 + 1},
				{Title: "Status", Size: 6 + 1, Style: func(s string) lipgloss.Style {
					switch s {
					case "OPEN":
						return lipgloss.NewStyle().Foreground(ansi.Green)
					case "CLOSED":
						return lipgloss.NewStyle().Foreground(ansi.Yellow)
					default:
						return lipgloss.Style{}
					}
				}},
				{Title: "Hostname", Size: -2},
				{Title: "Path", Size: -2},
				{Title: "Client", Size: 21 + 1},
				{Title: "Rx Bytes", Size: -1},
				{Title: "Tx Bytes", Size: -1},
				{Title: "Duration", Size: -1},
			}),
			Widget: Widget[*TableModel]{
				Model: newTableModel(channelsAccentColor, "Active Connections", "[1]"),
			},
		},
		perms: TableWidget{
			ColumnLayout: NewDirectionalLayout([]Cell{
				{Title: "Hostname", Size: -1, Style: func(s string) lipgloss.Style {
					if s == "(all)" {
						return lipgloss.NewStyle().Faint(true)
					}
					return lipgloss.Style{}
				}},
				{Title: "Port", Size: 8 + 1, Style: func(s string) lipgloss.Style {
					if strings.HasPrefix(s, "D ") {
						return lipgloss.NewStyle().Foreground(lipgloss.Blue)
					}
					return lipgloss.Style{}
				}},
				{Title: "Routes", Size: 7 + 1 + 1},
			}),
			Widget: Widget[*TableModel]{
				Model: newTableModel(permissionsAccentColor, "Client Requests", "[2]"),
			},
		},
		routes: TableWidget{
			ColumnLayout: NewDirectionalLayout([]Cell{
				{Title: "Status", Size: 6 + 1 + 1, Style: func(s string) lipgloss.Style {
					switch s {
					case "ACTIVE":
						return lipgloss.NewStyle().Foreground(ansi.Green)
					case "--":
						return lipgloss.NewStyle().Faint(true)
					default:
						return lipgloss.Style{}
					}
				}},
				{Title: "Remote", Size: -1},
				{Title: "Local", Size: -1},
			}),
			Widget: Widget[*TableModel]{
				Model: newTableModel(routesAccentColor, "Port Forward Status", "[3]"),
			},
		},
		logs: LogsWidget{
			Widget[*LogViewer]{
				Model: NewLogViewerModel(255, LogViewerStyles{
					Style:            lipgloss.NewStyle().Border(border),
					Focused:          lipgloss.NewStyle().BorderForeground(logsAccentColor),
					BorderTitleLeft:  "Logs",
					BorderTitleRight: "[4]",
					ShowTimestamp:    true,
					Timestamp:        textFaint,
				}),
			},
		},
		help: HelpWidget{
			Widget: Widget[*HelpModel]{
				Model: &HelpModel{
					Model: help.New(),
				},
			},
		},
		activeChannels:       map[uint32]*ChannelRow{},
		activePortForwards:   map[string]portforward.RoutePortForwardInfo{},
		permissionMatchCount: map[uint64]int{},
		keyMap: &KeyMap{
			FocusNext: key.NewBinding(
				key.WithKeys("tab"),
				key.WithHelp("tab", "select next panel"),
			),
			FocusPrev: key.NewBinding(
				key.WithKeys("shift+tab"),
				key.WithHelp("shift-tab", "select prev panel"),
			),
			Quit: key.NewBinding(
				key.WithKeys("q", "ctrl+c"),
				key.WithHelp("q", "quit"),
			),
			ShowHidePanel: key.NewBinding(
				key.WithKeys("1", "2", "3", "4"),
				key.WithHelp("1-4", "show/hide panels"),
			),
		},
	}
	m.tabOrder = m.buildTabOrder()
	m.keyMap.FocusedKeyMap = m.channels.Model.KeyMap()
	m.channels.Model.Focus()
	m.help.Model.DisplayedKeyMap = m.keyMap

	m.grid = m.buildGridLayout()

	m.channels.Model.SetColumns(m.channels.ColumnLayout.Resized(0).AsColumns())
	m.routes.Model.SetColumns(m.routes.ColumnLayout.Resized(0).AsColumns())
	m.perms.Model.SetColumns(m.perms.ColumnLayout.Resized(0).AsColumns())
	return m
}

func (m *TunnelStatusModel) buildGridLayout() *GridLayout {
	rows := []Row{}
	if !m.channels.Hidden {
		rows = append(rows, Row{
			Height: -2,
			Columns: []RowCell{
				{Title: "Channels", Size: -1, Rect: &m.channels.Rect},
			},
		})
	}
	if !m.perms.Hidden || !m.routes.Hidden {
		row := Row{
			Height: -2,
		}
		if !m.perms.Hidden {
			row.Columns = append(row.Columns, RowCell{Title: "Permissions", Size: -1, Rect: &m.perms.Rect})
		}
		if !m.routes.Hidden {
			row.Columns = append(row.Columns, RowCell{Title: "Routes", Size: -2, Rect: &m.routes.Rect})
		}
		rows = append(rows, row)
	}
	if !m.logs.Hidden {
		rows = append(rows, Row{
			Height: -1,
			Columns: []RowCell{
				{Title: "Logs", Size: -1, Rect: &m.logs.Rect},
			},
		})
	}
	return NewGridLayout(rows)
}

func (m *TunnelStatusModel) buildTabOrder() *ring.Ring {
	models := []any{}
	if !m.channels.Hidden {
		models = append(models, m.channels.Model)
	}
	if !m.perms.Hidden {
		models = append(models, m.perms.Model)
	}
	if !m.routes.Hidden {
		models = append(models, m.routes.Model)
	}
	if !m.logs.Hidden {
		models = append(models, m.logs.Model)
	}
	r := ring.New(len(models))
	for _, m := range models {
		r.Value = m
		r = r.Next()
	}
	return r
}

func (m *TunnelStatusModel) Init() tea.Cmd {
	return tea.Batch(
		tea.RequestBackgroundColor,
	)
}

var (
	textRed    = lipgloss.NewStyle().Foreground(ansi.Red)
	textYellow = lipgloss.NewStyle().Foreground(ansi.Yellow)
	textFaint  = lipgloss.NewStyle().Faint(true)
)

func (m *TunnelStatusModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	rebuildRouteTable := func() {
		rows := []table.Row{}
		for _, route := range m.allRoutes {
			status := "--"
			if _, ok := m.activePortForwards[route.ClusterID]; ok {
				status = "ACTIVE"
			}
			to, _, _ := route.Route.To.Flatten()
			remote := fmt.Sprintf("%s:%d", route.Route.From, route.Port)
			local := strings.Join(to, ",")
			rows = append(rows, table.Row{
				status,
				remote,
				local,
			})
		}
		m.routes.Model.SetRows(rows)
	}
	rebuildPermissionsTable := func() {
		rows := []table.Row{}
		for _, p := range m.permissions {
			sp := p.ServerPort()
			var pattern string
			if p.HostMatcher.IsMatchAll() {
				pattern = "(all)"
			} else {
				pattern = p.HostMatcher.InputPattern()
			}
			portStr := strconv.FormatInt(int64(sp.Value), 10)
			if sp.IsDynamic {
				portStr = "D " + portStr
			}
			numMatches := strconv.FormatInt(int64(m.permissionMatchCount[permissionHash(p)]), 10)
			rows = append(rows, table.Row{
				pattern,    // Hostname
				portStr,    // Port
				numMatches, // Match
			})
		}
		m.perms.Model.SetRows(rows)
	}
	switch msg := msg.(type) {
	case tea.ColorProfileMsg:
		m.profile = msg.Profile
	case tea.WindowSizeMsg:
		m.lastWidth, m.lastHeight = msg.Width, msg.Height
		m.resize(msg.Width, msg.Height)

	case tea.KeyPressMsg:
		switch {
		case key.Matches(msg, m.keyMap.FocusNext):
			if m.tabOrder.Len() > 0 {
				m.tabOrder.Value.(model).Blur()
				m.tabOrder = m.tabOrder.Next()
				m.tabOrder.Value.(model).Focus()
				m.keyMap.FocusedKeyMap = m.tabOrder.Value.(model).KeyMap()
			}
		case key.Matches(msg, m.keyMap.FocusPrev):
			if m.tabOrder.Len() > 0 {
				m.tabOrder.Value.(model).Blur()
				m.tabOrder = m.tabOrder.Prev()
				m.tabOrder.Value.(model).Focus()
				m.keyMap.FocusedKeyMap = m.tabOrder.Value.(model).KeyMap()
			}
		case key.Matches(msg, m.keyMap.Quit):
			return m, tea.Quit
		case key.Matches(msg, m.keyMap.ShowHidePanel):
			switch msg.Text {
			case "1":
				m.channels.Hidden = !m.channels.Hidden
				m.channels.Model.Blur()
			case "2":
				m.perms.Hidden = !m.perms.Hidden
				m.perms.Model.Blur()
			case "3":
				m.routes.Hidden = !m.routes.Hidden
				m.routes.Model.Blur()
			case "4":
				m.logs.Hidden = !m.logs.Hidden
				m.logs.Model.Blur()
			}
			m.keyMap.FocusedKeyMap = nil
			m.tabOrder = m.buildTabOrder()

			if m.tabOrder.Len() > 0 {
				for r := m.tabOrder.Next(); r != m.tabOrder; r = r.Next() {
					if r.Value.(model).Focused() {
						m.tabOrder = r
						break
					}
				}
				m.tabOrder.Value.(model).Focus()
				m.keyMap.FocusedKeyMap = m.tabOrder.Value.(model).KeyMap()
			}
			m.grid = m.buildGridLayout()
			m.resize(m.lastWidth, m.lastHeight)
		}
	case tea.MouseMsg:
		if m.lastView == nil {
			return m, nil
		}
		id := m.lastView.Hit(msg.Mouse().X, msg.Mouse().Y)
		if id == "" {
			return m, nil
		}
		// translate to the coordinate space of the layer
		relative := translateMouseEvent(msg, m.lastView.Get(id).Bounds())
		var cmd tea.Cmd
		switch id {
		case "":
			return m, nil
		case "1":
			m.setFocus(m.channels.Model)
			m.channels.Model.Model, cmd = m.channels.Model.Update(relative)
			return m, cmd
		case "2":
			m.setFocus(m.perms.Model)
			m.perms.Model.Model, cmd = m.perms.Model.Update(relative)
			return m, cmd
		case "3":
			m.setFocus(m.routes.Model)
			m.routes.Model.Model, cmd = m.routes.Model.Update(relative)
			return m, cmd
		case "4":
			m.setFocus(m.logs.Model)
			m.logs.Model, cmd = m.logs.Model.Update(relative)
			return m, cmd
		case "5":
			m.help.Model.Model, cmd = m.help.Model.Update(relative) // no-op?
			return m, cmd
		}
	case *extensions_ssh.ChannelEvent:
		switch event := msg.Event.(type) {
		case *extensions_ssh.ChannelEvent_InternalChannelOpened:
			ip, _, _ := net.SplitHostPort(event.InternalChannelOpened.PeerAddress)
			if ip == "" {
				ip = event.InternalChannelOpened.PeerAddress
			}
			m.logs.Model.Push(fmt.Sprintf("new connection from %s: %s", ip, event.InternalChannelOpened.Hostname))
			channelID := event.InternalChannelOpened.ChannelId
			m.activeChannels[channelID] = &ChannelRow{
				ID:          int32(channelID),
				Status:      "OPEN",
				Hostname:    event.InternalChannelOpened.Hostname,
				Path:        event.InternalChannelOpened.Path,
				PeerAddress: event.InternalChannelOpened.PeerAddress,
			}
		case *extensions_ssh.ChannelEvent_InternalChannelClosed:
			if ac, ok := m.activeChannels[event.InternalChannelClosed.ChannelId]; ok {
				ac.Status = "CLOSED"
				ac.Stats = event.InternalChannelClosed.Stats
			} else {
				panic("bug: channel state is invalid")
			}
			for _, diag := range event.InternalChannelClosed.Diagnostics {
				switch diag.Severity {
				case extensions_ssh.Diagnostic_Info:
					m.logs.Model.Push(diag.GetMessage())
				case extensions_ssh.Diagnostic_Warning:
					m.logs.Model.Push(textYellow.Render("warning: " + diag.GetMessage()))
					for _, hint := range diag.Hints {
						m.logs.Model.Push(textYellow.Faint(true).Render("   hint: " + hint))
					}
				case extensions_ssh.Diagnostic_Error:
					m.logs.Model.Push(textRed.Render("error: " + diag.GetMessage()))
					for _, hint := range diag.Hints {
						m.logs.Model.Push(textRed.Faint(true).Render(" hint: " + hint))
					}
				}
			}
		case *extensions_ssh.ChannelEvent_ChannelStats:
			for _, entry := range event.ChannelStats.GetStatsList().GetItems() {
				if ch, ok := m.activeChannels[entry.ChannelId]; ok {
					ch.Stats = entry
				}
			}
		}

		rows := make([]table.Row, 0, len(m.activeChannels))
		for _, cr := range slices.SortedFunc(maps.Values(m.activeChannels), func(a, b *ChannelRow) int {
			return cmp.Compare(a.ID, b.ID)
		}) {
			rows = append(rows, cr.ToRow())
		}
		m.channels.Model.SetRows(rows)
	case map[string]portforward.RoutePortForwardInfo:
		prevNumActiveClusters := len(m.activePortForwards)
		clear(m.permissionMatchCount)
		clear(m.activePortForwards)
		for clusterID, info := range msg {
			m.permissionMatchCount[permissionHash(info.Permission)]++
			m.activePortForwards[clusterID] = info
		}
		m.logs.Model.Push(fmt.Sprintf("active route endpoints updated (%d -> %d)",
			prevNumActiveClusters, len(m.activePortForwards)))
		rebuildRouteTable()
		rebuildPermissionsTable()
	case []portforward.RouteInfo:
		m.allRoutes = msg
		rebuildRouteTable()
		m.logs.Model.Push(fmt.Sprintf("routes updated (%d total)", len(msg)))
	case []portforward.Permission:
		m.permissions = msg
		rebuildPermissionsTable()
		m.logs.Model.Push(fmt.Sprintf("port-forward permissions updated (%d total)", len(msg)))
	}
	var cmd1, cmd2, cmd3, cmd4, cmd5 tea.Cmd
	m.channels.Model.Model, cmd1 = m.channels.Model.Update(msg)
	m.perms.Model.Model, cmd2 = m.perms.Model.Update(msg)
	m.routes.Model.Model, cmd3 = m.routes.Model.Update(msg)
	m.logs.Model, cmd4 = m.logs.Model.Update(msg)
	m.help.Model.Model, cmd5 = m.help.Model.Update(msg)
	return m, tea.Batch(cmd1, cmd2, cmd3, cmd4, cmd5)
}

func translateMouseEvent(msg tea.MouseMsg, rect image.Rectangle) tea.MouseMsg {
	switch msg := msg.(type) {
	case tea.MouseClickMsg:
		msg.X = msg.X - rect.Min.X
		msg.Y = msg.Y - rect.Min.Y
		return msg
	case tea.MouseMotionMsg:
		msg.X = msg.X - rect.Min.X
		msg.Y = msg.Y - rect.Min.Y
		return msg
	case tea.MouseReleaseMsg:
		msg.X = msg.X - rect.Min.X
		msg.Y = msg.Y - rect.Min.Y
		return msg
	case tea.MouseWheelMsg:
		msg.X = msg.X - rect.Min.X
		msg.Y = msg.Y - rect.Min.Y
		return msg
	default:
		panic("unknown mouse message type")
	}
}

func (m *TunnelStatusModel) setFocus(toFocus model) {
	if toFocus.Focused() || m.tabOrder == nil {
		return
	}
	if m.tabOrder.Value.(model) == toFocus {
		toFocus.Focus()
		m.keyMap.FocusedKeyMap = toFocus.KeyMap()
		return
	}
	m.tabOrder.Value.(model).Blur()
	for r := m.tabOrder.Next(); r != m.tabOrder; r = r.Next() {
		if r.Value.(model) == toFocus {
			m.tabOrder = r
			break
		}
	}
	m.tabOrder.Value.(model).Focus()
	m.keyMap.FocusedKeyMap = m.tabOrder.Value.(model).KeyMap()
}

func (m *TunnelStatusModel) resize(width int, height int) {
	m.grid.Resize(width, height-1) // reserve space for help
	m.channels.Model.SetSizeAndColumns(m.channels.Rect.Dx(), m.channels.Rect.Dy(), m.channels.ColumnLayout.Resized(m.channels.Rect.Dx()).AsColumns())
	m.perms.Model.SetSizeAndColumns(m.perms.Rect.Dx(), m.perms.Rect.Dy(), m.perms.ColumnLayout.Resized(m.perms.Rect.Dx()).AsColumns())
	m.routes.Model.SetSizeAndColumns(m.routes.Rect.Dx(), m.routes.Rect.Dy(), m.routes.ColumnLayout.Resized(m.routes.Rect.Dx()).AsColumns())
	m.logs.Model.SetSize(m.logs.Rect.Dx(), m.logs.Rect.Dy())

	m.help.Model.Width = m.help.Rect.Dx()
	m.help.Rect = image.Rectangle{
		Min: image.Pt(0, height-1),
		Max: image.Pt(width, height),
	}
}

func (m *TunnelStatusModel) View() tea.View {
	canvas := lipgloss.NewCanvas()
	if !m.channels.Hidden {
		canvas.AddLayers(m.channels.ToLayer().ID("1").Z(2))
	}
	if !m.perms.Hidden {
		canvas.AddLayers(m.perms.ToLayer().ID("2").Z(2))
	}
	if !m.routes.Hidden {
		canvas.AddLayers(m.routes.ToLayer().ID("3").Z(2))
	}
	if !m.logs.Hidden {
		canvas.AddLayers(m.logs.ToLayer().ID("4").Z(2))
	}
	canvas.AddLayers(m.help.ToLayer().ID("5").Z(2))
	canvas.AddLayers(m.newBackgroundLayer())

	m.lastView = canvas
	view := tea.NewView(canvas)
	view.AltScreen = true
	view.MouseMode = tea.MouseModeCellMotion
	return view
}

func (m *TunnelStatusModel) newBackgroundLayer() *lipgloss.Layer {
	l := lipgloss.NewLayer("Press [1-4] to show panels")
	return l.X(m.lastWidth/2 - l.GetWidth()/2).Y(m.lastHeight / 2).Z(1)
}

func permissionHash(p portforward.Permission) uint64 {
	d := hashutil.NewDigest()
	d.WriteStringWithLen(p.HostMatcher.InputPattern())
	d.WriteUint32(p.RequestedPort)
	d.WriteUint32(uint32(p.VirtualPort))
	return d.Sum64()
}
