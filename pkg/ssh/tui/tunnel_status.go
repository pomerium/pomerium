package tui

import (
	"container/ring"
	"context"
	"fmt"
	"image"
	"maps"
	"strconv"
	"strings"
	"time"

	"charm.land/bubbles/v2/key"
	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"
	"github.com/charmbracelet/colorprofile"
	uv "github.com/charmbracelet/ultraviolet"
	datav3 "github.com/envoyproxy/go-control-plane/envoy/data/core/v3"

	extensions_ssh "github.com/pomerium/envoy-custom/api/extensions/filters/network/ssh"
	"github.com/pomerium/pomerium/internal/hashutil"
	"github.com/pomerium/pomerium/pkg/ssh/model"
	"github.com/pomerium/pomerium/pkg/ssh/portforward"
	"github.com/pomerium/pomerium/pkg/ssh/tui/components/header"
	"github.com/pomerium/pomerium/pkg/ssh/tui/components/help"
	"github.com/pomerium/pomerium/pkg/ssh/tui/components/logviewer"
	"github.com/pomerium/pomerium/pkg/ssh/tui/components/menu"
	"github.com/pomerium/pomerium/pkg/ssh/tui/components/table"
	"github.com/pomerium/pomerium/pkg/ssh/tui/core"
	"github.com/pomerium/pomerium/pkg/ssh/tui/core/layout"
	"github.com/pomerium/pomerium/pkg/ssh/tui/style"
)

type TunnelStatusProgram struct {
	*tea.Program
	portForwardEndpoints map[string]portforward.RoutePortForwardInfo
}

func NewTunnelStatusProgram(ctx context.Context, theme *style.Theme, opts ...tea.ProgramOption) *TunnelStatusProgram {
	model := NewTunnelStatusModel(theme)
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

type ChannelUpdate struct {
	model.Channel
	model.Index
}

func channelToRow(cr model.Channel) table.Row {
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

type KeyMap struct {
	FocusNext     key.Binding
	FocusPrev     key.Binding
	Quit          key.Binding
	ShowHidePanel key.Binding
	FocusedKeyMap help.KeyMap
	ModalKeyMap   help.KeyMap
}

// FullHelp implements help.KeyMap.
func (k KeyMap) FullHelp() [][]key.Binding {
	var fh [][]key.Binding
	if k.ModalKeyMap != nil {
		return k.ModalKeyMap.FullHelp()
	} else if k.FocusedKeyMap != nil {
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
	if k.ModalKeyMap != nil {
		return k.ModalKeyMap.ShortHelp()
	} else if k.FocusedKeyMap != nil {
		fh = k.FocusedKeyMap.ShortHelp()
	}
	return append([]key.Binding{k.Quit, k.FocusNext, k.ShowHidePanel}, fh...)
}

type TunnelStatusModel struct {
	theme                  *style.Theme
	header                 *header.Widget
	channels               *table.Widget
	routes                 *table.Widget
	perms                  *table.Widget
	logs                   *logviewer.Widget
	help                   *help.Widget
	contextMenu            *menu.Widget
	mouseMode              tea.MouseMode
	contextMenuAnchor      *uv.Position
	ignoreNextMouseRelease bool
	noChangesInLastUpdate  bool

	grid    *layout.GridLayout
	profile colorprofile.Profile

	activePortForwards    map[string]portforward.RoutePortForwardInfo
	clusterHealth         map[string]string
	clusterEndpointStatus map[string]string
	permissionMatchCount  map[uint64]int
	allRoutes             []portforward.RouteInfo
	permissions           []portforward.Permission

	keyMap *KeyMap

	tabOrder              *ring.Ring
	lastWidth, lastHeight int
	lastView              *lipgloss.Canvas
}

var AppName string

func init() {
	if AppName == "" {
		AppName = "Pomerium"
	}
}

const (
	IDHeader      = "Header"
	IDChannels    = "Channels"
	IDPermissions = "Permissions"
	IDRoutes      = "Routes"
	IDLogs        = "Logs"
	IDHelp        = "Help"
	IDMenu        = "Menu"
)

func NewTunnelStatusModel(theme *style.Theme) *TunnelStatusModel {
	m := &TunnelStatusModel{
		theme:                 theme,
		activePortForwards:    map[string]portforward.RoutePortForwardInfo{},
		clusterEndpointStatus: map[string]string{},
		clusterHealth:         map[string]string{},
		permissionMatchCount:  map[uint64]int{},
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

		mouseMode: tea.MouseModeCellMotion,
	}

	m.header = core.NewWidget(IDHeader, header.NewHeaderModel(
		[]header.HeaderSegment{
			{
				Label:   "App Name",
				Content: func(*model.Session) string { return AppName },
				Style: lipgloss.NewStyle().
					BorderStyle(style.SingleLineRoundedBorder).
					BorderLeft(true).
					BorderRight(true).
					Bold(true).
					Background(theme.Colors.BrandPrimary.Normal).
					Foreground(theme.Colors.BrandPrimary.ContrastingText).
					BorderForeground(theme.Colors.BrandPrimary.Normal),
			},
		},
		[]header.HeaderSegment{
			{
				Label: "Session ID",
				Content: func(s *model.Session) string {
					if s == nil {
						return ""
					}
					return s.SessionID
				},
				Style: lipgloss.NewStyle().Foreground(lipgloss.White).Faint(true).PaddingLeft(1).PaddingRight(1),
			},
			{
				Label: "Client IP",
				Content: func(s *model.Session) string {
					if s == nil {
						return ""
					}
					return s.ClientIP
				},
				Style: lipgloss.NewStyle().Foreground(lipgloss.White).Faint(true).PaddingLeft(1).PaddingRight(1),
			},
			{
				Label: "Email",
				Content: func(s *model.Session) string {
					if s == nil {
						return ""
					}
					var email string
					if id := s.Claims["email"]; len(id) > 0 {
						email = id[0].(string)
					} else if id := s.Claims["sub"]; len(id) > 0 {
						email = id[0].(string)
					} else if id := s.Claims["name"]; len(id) > 0 {
						email = id[0].(string)
					}
					return email
				},
				OnClick: func(xy uv.Position) tea.Cmd {
					return func() tea.Msg {
						global := m.header.Bounds().Min.Add(xy)
						return menu.ShowMsg{
							Anchor: global,
							Entries: []menu.Entry{
								{
									Label:      "Log Out",
									OnSelected: logviewer.AddLog("log out selected"),
								},
								{
									Label:      "Show User Details",
									OnSelected: logviewer.AddLog("show user details selected"),
								},
							},
						}
					}
				},
				Style: lipgloss.NewStyle().
					BorderStyle(style.SingleLineRoundedBorder).
					BorderLeft(true).
					BorderRight(true).
					Bold(true).
					Foreground(lipgloss.Black).
					Background(lipgloss.BrightWhite).
					BorderForeground(lipgloss.BrightWhite),
			},
		},
	))

	healthCheckStyle := lipgloss.NewStyle().Foreground(theme.Colors.TextFaint1).Transform(func(string) string {
		return "Health Check"
	})
	m.channels = core.NewWidget(string(IDChannels),
		table.NewModel(
			layout.NewDirectionalLayout([]layout.Cell{
				{Title: "Channel", Size: 7 + 1 + 1},
				{Title: "Status", Size: 6 + 1, Style: func(s string) lipgloss.Style {
					switch s {
					case "OPEN":
						return m.theme.TextStatusHealthy
					case "CLOSED":
						return m.theme.TextStatusDegraded
					default:
						return lipgloss.Style{}
					}
				}},
				{Title: "Hostname", Size: -2},
				{Title: "Path", Size: -2},
				{Title: "Client", Size: 21 + 1, Style: func(s string) lipgloss.Style {
					if s == "envoy_health_check" {
						return healthCheckStyle
					}
					return lipgloss.Style{}
				}},
				{Title: "Rx Bytes", Size: -1},
				{Title: "Tx Bytes", Size: -1},
				{Title: "Duration", Size: -1},
			}), table.Config{
				Styles: table.NewStyles(theme, theme.Colors.Accent1),
				Options: table.Options{
					BorderTitleLeft:  "Active Connections",
					BorderTitleRight: "[1]",
				},
			}),
	)

	m.perms = core.NewWidget(IDPermissions, table.NewModel(
		layout.NewDirectionalLayout([]layout.Cell{
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
		}), table.Config{
			Styles: table.NewStyles(theme, theme.Colors.Accent2),
			Options: table.Options{
				BorderTitleLeft:  "Client Requests",
				BorderTitleRight: "[2]",
			},
		}),
	)

	m.routes = core.NewWidget(IDRoutes, table.NewModel(
		layout.NewDirectionalLayout([]layout.Cell{
			{Title: "Status", Size: 10, Style: func(s string) lipgloss.Style {
				switch s {
				case "ACTIVE":
					return m.theme.TextStatusHealthy
				case "INACTIVE":
					return m.theme.TextStatusUnknown
				case "--":
					return m.theme.TextStatusUnknown
				default:
					return lipgloss.Style{}
				}
			}},
			{Title: "Health", Size: 10, Style: func(s string) lipgloss.Style {
				switch s {
				case "HEALTHY":
					return m.theme.TextStatusHealthy
				case "UNHEALTHY", "ERROR":
					return m.theme.TextStatusUnhealthy
				case "DEGRADED":
					return m.theme.TextStatusDegraded
				case "UNKNOWN", "--":
					return m.theme.TextStatusUnknown
				default:
					return lipgloss.Style{}
				}
			}},
			{Title: "Remote", Size: -1},
			{Title: "Local", Size: -1},
		}), table.Config{
			Styles: table.NewStyles(theme, theme.Colors.Accent3),
			Options: table.Options{
				BorderTitleLeft:  "Port Forward Status",
				BorderTitleRight: "[3]",
			},
		}),
	)
	m.routes.Model.OnRowMenuRequested = func(pos uv.Position, index int) tea.Cmd {
		global := m.routes.Bounds().Min.Add(pos)
		return menu.ShowMenu(global, []menu.Entry{
			{
				Label: "Edit ",
				OnSelected: func() tea.Msg {
					return nil
				},
			},
		})
	}

	m.logs = core.NewWidget(IDLogs, logviewer.NewModel(logviewer.Config{
		Styles: logviewer.NewStyles(theme, theme.Colors.Accent4),
		Options: logviewer.Options{
			BorderTitleLeft:  "Logs",
			BorderTitleRight: "[4]",
			ShowTimestamp:    true,
			BufferSize:       256,
		},
	}))

	m.help = core.NewWidget(IDHelp, help.NewModel(theme))

	m.contextMenu = core.NewWidget(IDMenu, menu.NewContextMenuModel())
	m.contextMenu.Hidden = true

	m.tabOrder = m.buildTabOrder()
	m.keyMap.FocusedKeyMap = m.channels.Model.KeyMap()
	m.channels.Model.Focus()
	m.help.Model.DisplayedKeyMap = m.keyMap

	m.grid = m.buildGridLayout()
	return m
}

func (m *TunnelStatusModel) buildGridLayout() *layout.GridLayout {
	rows := []layout.Row{}
	rows = append(rows, layout.Row{
		Height: 1,
		Columns: []layout.RowCell{
			{Title: "Session", Size: -1, Widget: m.header},
		},
	})
	if !m.channels.Hidden {
		rows = append(rows, layout.Row{
			Height: -2,
			Columns: []layout.RowCell{
				{Title: "Channels", Size: -1, Widget: m.channels},
			},
		})
	}
	if !m.perms.Hidden || !m.routes.Hidden {
		row := layout.Row{
			Height: -2,
		}
		if !m.perms.Hidden {
			row.Columns = append(row.Columns, layout.RowCell{Title: "Permissions", Size: -1, Widget: m.perms})
		}
		if !m.routes.Hidden {
			row.Columns = append(row.Columns, layout.RowCell{Title: "Routes", Size: -2, Widget: m.routes})
		}
		rows = append(rows, row)
	}
	if !m.logs.Hidden {
		rows = append(rows, layout.Row{
			Height: -1,
			Columns: []layout.RowCell{
				{Title: "Logs", Size: -1, Widget: m.logs},
			},
		})
	}
	if !m.help.Hidden {
		rows = append(rows, layout.Row{
			Height: 1,
			Columns: []layout.RowCell{
				{Title: "Help", Size: -1, Widget: m.help},
			},
		})
	}
	return layout.NewGridLayout(rows)
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

func (m *TunnelStatusModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	m.noChangesInLastUpdate = false
	switch msg := msg.(type) {
	case tea.ColorProfileMsg:
		m.profile = msg.Profile
	case tea.WindowSizeMsg:
		m.lastWidth, m.lastHeight = msg.Width, msg.Height
		m.resize(msg.Width, msg.Height)
		return m, nil
	case tea.KeyPressMsg:
		if !m.contextMenu.Hidden {
			// context menu will steal focus
			return m, m.contextMenu.Model.Update(msg)
		}
		switch {
		case key.Matches(msg, m.keyMap.FocusNext):
			if m.tabOrder.Len() > 0 {
				m.tabOrder.Value.(core.Model).Blur()
				m.tabOrder = m.tabOrder.Next()
				m.tabOrder.Value.(core.Model).Focus()
				m.keyMap.FocusedKeyMap = m.tabOrder.Value.(core.Model).KeyMap()
			}
		case key.Matches(msg, m.keyMap.FocusPrev):
			if m.tabOrder.Len() > 0 {
				m.tabOrder.Value.(core.Model).Blur()
				m.tabOrder = m.tabOrder.Prev()
				m.tabOrder.Value.(core.Model).Focus()
				m.keyMap.FocusedKeyMap = m.tabOrder.Value.(core.Model).KeyMap()
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
					if r.Value.(core.Model).Focused() {
						m.tabOrder = r
						break
					}
				}
				m.tabOrder.Value.(core.Model).Focus()
				m.keyMap.FocusedKeyMap = m.tabOrder.Value.(core.Model).KeyMap()
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
		if !m.contextMenu.Hidden && id != IDMenu {
			switch msg := msg.(type) {
			case tea.MouseClickMsg:
				// clicked outside the context menu
				m.hideContextMenu()
				m.ignoreNextMouseRelease = true
				return m, nil
			case tea.MouseReleaseMsg:
				// We may get a mouse release immediately in the same position as the
				// anchor.
				if uv.Pos(msg.X, msg.Y).In(uv.Rect(m.contextMenuAnchor.X-1, m.contextMenuAnchor.Y-1, 3, 2)) {
					return m, nil
				}
				m.contextMenu.Hidden = true
				m.keyMap.ModalKeyMap = nil
			default:
				// ignore motion/scroll if they happen outside the context menu
				m.noChangesInLastUpdate = true
				return m, nil
			}
		} else if m.ignoreNextMouseRelease {
			switch msg.(type) {
			case tea.MouseReleaseMsg:
				m.ignoreNextMouseRelease = false
				return m, nil
			}
		}
		switch id {
		case "":
			return m, nil
		case IDMenu:
			return m, m.contextMenu.Model.Update(relative)
		case IDHeader:
			return m, m.header.Model.Update(relative)
		case IDChannels:
			m.setFocus(m.channels.Model)
			return m, m.channels.Model.Update(relative)
		case IDPermissions:
			m.setFocus(m.perms.Model)
			return m, m.perms.Model.Update(relative)
		case IDRoutes:
			m.setFocus(m.routes.Model)
			return m, m.routes.Model.Update(relative)
		case IDLogs:
			m.setFocus(m.logs.Model)
			return m, m.logs.Model.Update(relative)
		case IDHelp:
			return m, m.help.Model.Update(relative)
		}
	case ChannelUpdate:
		m.channels.Model.UpdateRow(int(msg.Index), channelToRow(msg.Channel))
		return m, nil
	case model.Session:
		m.header.Model.UpdateSession(&msg)
		return m, nil
	case menu.ShowMsg:
		m.showContextMenu(msg)
		return m, nil
	case menu.HideMsg:
		m.hideContextMenu()
		return m, nil
	case logviewer.AddLogMsg:
		m.logs.Model.Push(msg.Message)
		return m, nil
	case *extensions_ssh.Diagnostic:
		switch msg.Severity {
		case extensions_ssh.Diagnostic_Info:
			m.logs.Model.Push(msg.GetMessage())
		case extensions_ssh.Diagnostic_Warning:
			m.logs.Model.Push(m.theme.TextWarning.Render("warning: " + msg.GetMessage()))
			for _, hint := range msg.Hints {
				m.logs.Model.Push(m.theme.TextWarning.Faint(true).Render("   hint: " + hint))
			}
		case extensions_ssh.Diagnostic_Error:
			m.logs.Model.Push(m.theme.TextError.Render("error: " + msg.GetMessage()))
			for _, hint := range msg.Hints {
				m.logs.Model.Push(m.theme.TextError.Faint(true).Render(" hint: " + hint))
			}
		}
		return m, nil
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
		m.rebuildRouteTable()
		m.rebuildPermissionsTable()
		return m, nil
	case []portforward.RouteInfo:
		m.allRoutes = msg
		m.rebuildRouteTable()
		m.logs.Model.Push(fmt.Sprintf("routes updated (%d total)", len(msg)))
		return m, nil
	case []portforward.Permission:
		m.permissions = msg
		m.rebuildPermissionsTable()
		m.logs.Model.Push(fmt.Sprintf("port-forward permissions updated (%d total)", len(msg)))
		return m, nil
	case *datav3.HealthCheckEvent:
		var md extensions_ssh.EndpointMetadata
		err := msg.Metadata.TypedFilterMetadata["com.pomerium.ssh.endpoint"].UnmarshalTo(&md)
		if err != nil {
			panic(err)
		}
		affected := m.activePortForwards[msg.ClusterName]
		switch event := msg.Event.(type) {
		case *datav3.HealthCheckEvent_AddHealthyEvent:
			m.clusterHealth[msg.ClusterName] = "HEALTHY"
			m.clusterEndpointStatus[msg.ClusterName] = "ACTIVE"
		case *datav3.HealthCheckEvent_EjectUnhealthyEvent:
			m.clusterHealth[msg.ClusterName] = "UNHEALTHY"
			m.clusterEndpointStatus[msg.ClusterName] = "INACTIVE"
		case *datav3.HealthCheckEvent_DegradedHealthyHost:
			m.clusterHealth[msg.ClusterName] = "DEGRADED"
		case *datav3.HealthCheckEvent_HealthCheckFailureEvent:
			m.clusterHealth[msg.ClusterName] = "UNHEALTHY"
		case *datav3.HealthCheckEvent_NoLongerDegradedHost:
			m.clusterHealth[msg.ClusterName] = "HEALTHY"
		case *datav3.HealthCheckEvent_SuccessfulHealthCheckEvent:
			m.clusterHealth[msg.ClusterName] = "HEALTHY"
		default:
			panic(fmt.Sprintf("unexpected corev3.isHealthCheckEvent_Event: %#v", event))
		}
		m.rebuildRouteTable()
		m.logs.Model.Push(fmt.Sprintf("health update: %s: %s", affected.Hostname, m.clusterHealth[msg.ClusterName]))
		return m, nil
	}

	return m, tea.Batch(
		m.channels.Model.Update(msg),
		m.perms.Model.Update(msg),
		m.routes.Model.Update(msg),
		m.logs.Model.Update(msg),
		m.help.Model.Update(msg),
		m.header.Model.Update(msg),
	)
}

func (m *TunnelStatusModel) rebuildRouteTable() {
	rows := []table.Row{}
	for _, route := range m.allRoutes {
		status := "--"
		health := "--"
		if _, ok := m.activePortForwards[route.ClusterID]; ok {
			status = "ACTIVE"
			if stat, ok := m.clusterEndpointStatus[route.ClusterID]; ok {
				status = stat
			}
			health = m.clusterHealth[route.ClusterID]
			if health == "" {
				health = "UNKNOWN"
			}
		}

		to, _, _ := route.To.Flatten()
		remote := fmt.Sprintf("%s:%d", route.From, route.Port)
		local := strings.Join(to, ",")
		rows = append(rows, table.Row{
			status,
			health,
			remote,
			local,
		})
	}
	m.routes.Model.SetRows(rows)
}

func (m *TunnelStatusModel) rebuildPermissionsTable() {
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

func (m *TunnelStatusModel) showContextMenu(msg menu.ShowMsg) {
	m.contextMenu.Model.SetEntries(msg.Entries)
	m.contextMenu.Model.Hovered = 0
	m.contextMenuAnchor = &msg.Anchor
	width, height := m.contextMenu.Model.ContentDimensions()
	x, y := msg.Anchor.X, msg.Anchor.Y+1
	if x+width >= m.lastWidth {
		// shift left
		x -= (x + width) - m.lastWidth
	}
	if y+height >= m.lastHeight {
		// shift up
		y += (y + height) - m.lastHeight
	}
	m.contextMenu.SetBounds(uv.Rect(x, y, width, height))
	m.contextMenu.Hidden = false
	m.keyMap.ModalKeyMap = m.contextMenu.Model.Bindings

	m.mouseMode = tea.MouseModeAllMotion
}

func (m *TunnelStatusModel) hideContextMenu() {
	m.contextMenu.Hidden = true
	m.keyMap.ModalKeyMap = nil
	m.mouseMode = tea.MouseModeCellMotion
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

func (m *TunnelStatusModel) setFocus(toFocus core.Model) {
	if toFocus.Focused() || m.tabOrder == nil {
		return
	}
	if m.tabOrder.Value.(core.Model) == toFocus {
		toFocus.Focus()
		m.keyMap.FocusedKeyMap = toFocus.KeyMap()
		return
	}
	m.tabOrder.Value.(core.Model).Blur()
	for r := m.tabOrder.Next(); r != m.tabOrder; r = r.Next() {
		if r.Value.(core.Model) == toFocus {
			m.tabOrder = r
			break
		}
	}
	m.tabOrder.Value.(core.Model).Focus()
	m.keyMap.FocusedKeyMap = m.tabOrder.Value.(core.Model).KeyMap()
}

func (m *TunnelStatusModel) resize(width int, height int) {
	m.grid.Resize(width, height-1) // reserve space for help
	m.channels.Model.SetSizeAndColumns(m.channels.Rect.Dx(), m.channels.Rect.Dy(), m.channels.ColumnLayout.Resized(m.channels.Rect.Dx()).AsColumns())
	m.perms.Model.SetSizeAndColumns(m.perms.Rect.Dx(), m.perms.Rect.Dy(), m.perms.ColumnLayout.Resized(m.perms.Rect.Dx()).AsColumns())
	m.routes.Model.SetSizeAndColumns(m.routes.Rect.Dx(), m.routes.Rect.Dy(), m.routes.ColumnLayout.Resized(m.routes.Rect.Dx()).AsColumns())
	m.logs.Model.SetSize(m.logs.Rect.Dx(), m.logs.Rect.Dy())

	m.help.Model.SetWidth(m.help.Rect.Dx())
	m.help.Rect = image.Rectangle{
		Min: image.Pt(0, height-1),
		Max: image.Pt(width, height),
	}
}

func (m *TunnelStatusModel) View() tea.View {
	if !m.noChangesInLastUpdate || m.lastView == nil {
		canvas := lipgloss.NewCanvas()
		layers := []*lipgloss.Layer{
			m.header.Z(2),
			m.channels.Z(2),
			m.perms.Z(2),
			m.routes.Z(2),
			m.logs.Z(2),
			m.help.Z(2),
			m.newBackgroundLayer().Z(1),
		}
		if !m.contextMenu.Hidden {
			layers = append(layers, m.contextMenu.Z(99))
		}
		canvas.AddLayers(layers...)

		m.lastView = canvas
	}
	return tea.View{
		ContentDrawable: m.lastView,
		AltScreen:       true,
		MouseMode:       m.mouseMode,
	}
}

func (m *TunnelStatusModel) newBackgroundLayer() *lipgloss.Layer {
	l := lipgloss.NewLayer("Press [1-4] to show panels")
	return l.X(m.lastWidth/2 - l.GetWidth()/2).Y(m.lastHeight / 2)
}

func permissionHash(p portforward.Permission) uint64 {
	d := hashutil.NewDigest()
	d.WriteStringWithLen(p.HostMatcher.InputPattern())
	d.WriteUint32(p.RequestedPort)
	d.WriteUint32(uint32(p.VirtualPort))
	return d.Sum64()
}
