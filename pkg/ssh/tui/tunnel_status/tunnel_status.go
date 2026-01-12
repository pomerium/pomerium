package tunnel_status

import (
	"container/ring"
	"fmt"
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
	"github.com/pomerium/pomerium/pkg/ssh/tui/core"
	"github.com/pomerium/pomerium/pkg/ssh/tui/core/layout"
	"github.com/pomerium/pomerium/pkg/ssh/tui/widgets/header"
	"github.com/pomerium/pomerium/pkg/ssh/tui/widgets/help"
	"github.com/pomerium/pomerium/pkg/ssh/tui/widgets/logviewer"
	"github.com/pomerium/pomerium/pkg/ssh/tui/widgets/menu"
	"github.com/pomerium/pomerium/pkg/ssh/tui/widgets/table"
)

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
	return append([]key.Binding{k.Quit, k.FocusNext, k.ShowHidePanel}, fh...)
}

type Model struct {
	config                 Config
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

const (
	RoutesColStatus = iota
	RoutesColHealth
	RoutesColRemote
	RoutesColLocal
)

const (
	PermsColHostname = iota
	PermsColPort
	PermsColRoutes
)

const (
	ChannelsColID = iota
	ChannelsColStatus
	ChannelsColHostname
	ChannelsColPath
	ChannelsColClient
	ChannelsColRxBytes
	ChannelsColTxBytes
	ChannelsColDuration
)

func NewTunnelStatusModel(config Config) *Model {
	m := &Model{
		config:                config,
		activePortForwards:    map[string]portforward.RoutePortForwardInfo{},
		clusterEndpointStatus: map[string]string{},
		clusterHealth:         map[string]string{},
		permissionMatchCount:  map[uint64]int{},

		mouseMode: tea.MouseModeCellMotion,
	}

	m.header = core.NewWidget(IDHeader, header.NewModel(header.Config{
		Options: header.Options{
			LeftAlignedSegments:  config.Header.LeftAlignedSegments(config.Styles.HeaderSegments),
			RightAlignedSegments: config.Header.RightAlignedSegments(config.Styles.HeaderSegments),
		},
	}))
	m.header.Hidden = config.Header.Hide

	m.channels = core.NewWidget(string(IDChannels),
		table.NewModel(
			table.Config{
				Styles: config.Styles.Channels.Styles,
				Options: table.Options{
					ColumnLayout: layout.NewDirectionalLayout([]layout.Cell{
						ChannelsColID:       {Title: "Channel", Size: 7 + 1 + 1, Style: config.Styles.Channels.ColumnStyles["Channel"]},
						ChannelsColStatus:   {Title: "Status", Size: 6 + 1, Style: config.Styles.Channels.ColumnStyles["Status"]},
						ChannelsColHostname: {Title: "Hostname", Size: -2, Style: config.Styles.Channels.ColumnStyles["Hostname"]},
						ChannelsColPath:     {Title: "Path", Size: -2, Style: config.Styles.Channels.ColumnStyles["Path"]},
						ChannelsColClient:   {Title: "Client", Size: 21 + 1, Style: config.Styles.Channels.ColumnStyles["Client"]},
						ChannelsColRxBytes:  {Title: "Rx Bytes", Size: -1, Style: config.Styles.Channels.ColumnStyles["Rx Bytes"]},
						ChannelsColTxBytes:  {Title: "Tx Bytes", Size: -1, Style: config.Styles.Channels.ColumnStyles["Tx Bytes"]},
						ChannelsColDuration: {Title: "Duration", Size: -1, Style: config.Styles.Channels.ColumnStyles["Duration"]},
					}),
					KeyMap:           table.DefaultKeyMap,
					BorderTitleLeft:  config.Channels.Title,
					BorderTitleRight: "[1]",
				},
			}),
	)
	m.channels.Hidden = config.Channels.StartHidden
	m.channels.Model.OnRowMenuRequested = func(pos uv.Position, index int) tea.Cmd {
		return menu.ShowMenu(pos, m.config.Channels.RowContextOptions(m.channels.Model, index))
	}

	m.perms = core.NewWidget(IDPermissions, table.NewModel(
		table.Config{
			Styles: config.Styles.Permissions.Styles,
			Options: table.Options{
				ColumnLayout: layout.NewDirectionalLayout([]layout.Cell{
					PermsColHostname: {Title: "Hostname", Size: -1, Style: config.Styles.Permissions.ColumnStyles["Hostname"]},
					PermsColPort:     {Title: "Port", Size: 8 + 1, Style: config.Styles.Permissions.ColumnStyles["Port"]},
					PermsColRoutes:   {Title: "Routes", Size: 7 + 1 + 1, Style: config.Styles.Permissions.ColumnStyles["Routes"]},
				}),
				KeyMap:           table.DefaultKeyMap,
				BorderTitleLeft:  config.Permissions.Title,
				BorderTitleRight: "[2]",
			},
		}),
	)
	m.perms.Hidden = config.Permissions.StartHidden
	m.perms.Model.OnRowMenuRequested = func(pos uv.Position, index int) tea.Cmd {
		return menu.ShowMenu(pos, m.config.Permissions.RowContextOptions(m.perms.Model, index))
	}

	m.routes = core.NewWidget(IDRoutes, table.NewModel(
		table.Config{
			Styles: config.Styles.Routes.Styles,
			Options: table.Options{
				ColumnLayout: layout.NewDirectionalLayout([]layout.Cell{
					RoutesColStatus: {Title: "Status", Size: 10, Style: config.Styles.Routes.ColumnStyles["Status"]},
					RoutesColHealth: {Title: "Health", Size: 10, Style: config.Styles.Routes.ColumnStyles["Health"]},
					RoutesColRemote: {Title: "Remote", Size: -1, Style: config.Styles.Routes.ColumnStyles["Remote"]},
					RoutesColLocal:  {Title: "Local", Size: -1, Style: config.Styles.Routes.ColumnStyles["Local"]},
				}),
				KeyMap:           table.DefaultKeyMap,
				BorderTitleLeft:  config.Routes.Title,
				BorderTitleRight: "[3]",
			},
		}),
	)
	m.routes.Hidden = config.Routes.StartHidden
	m.routes.Model.OnRowMenuRequested = func(pos uv.Position, index int) tea.Cmd {
		return menu.ShowMenu(pos, m.config.Routes.RowContextOptions(m.routes.Model, index))
	}

	m.logs = core.NewWidget(IDLogs, logviewer.NewModel(logviewer.Config{
		Styles: config.Styles.Logs.Styles,
		Options: logviewer.Options{
			KeyMap:           logviewer.DefaultKeyMap,
			BorderTitleLeft:  config.Logs.Title,
			BorderTitleRight: "[4]",
			ShowTimestamp:    true,
			BufferSize:       config.Logs.Scrollback,
		},
	}))
	m.logs.Hidden = config.Logs.StartHidden

	m.help = core.NewWidget(IDHelp, help.NewModel(help.Config{
		Styles:  config.Styles.Help,
		Options: help.DefaultOptions,
	}))
	m.help.Hidden = config.Help.Hide

	m.contextMenu = core.NewWidget(IDMenu, menu.NewContextMenuModel(menu.Config{
		Styles: config.Styles.ContextMenu,
		Options: menu.Options{
			KeyMap: menu.DefaultKeyMap,
		},
	}))
	m.contextMenu.Hidden = true

	m.tabOrder = m.buildTabOrder()
	m.config.KeyMap.focusedKeyMap = m.channels.Model.KeyMap()
	m.channels.Model.Focus()
	m.help.Model.DisplayedKeyMap = m.config.KeyMap

	m.grid = m.buildGridLayout()
	return m
}

func (m *Model) buildGridLayout() *layout.GridLayout {
	// Note: Title fields here are unused, but they are set to widget IDs for
	// ease of debugging
	rows := []layout.Row{}
	if !m.header.Hidden {
		rows = append(rows, layout.Row{
			Height:  1,
			Columns: []layout.RowCell{{Title: IDHeader, Size: -1, Widget: m.header}},
		})
	}
	if !m.channels.Hidden {
		rows = append(rows, layout.Row{
			Height:  -2,
			Columns: []layout.RowCell{{Title: IDChannels, Size: -1, Widget: m.channels}},
		})
	}
	if !m.perms.Hidden || !m.routes.Hidden {
		row := layout.Row{
			Height: -2,
		}
		if !m.perms.Hidden {
			row.Columns = append(row.Columns, layout.RowCell{Title: IDPermissions, Size: -1, Widget: m.perms})
		}
		if !m.routes.Hidden {
			row.Columns = append(row.Columns, layout.RowCell{Title: IDRoutes, Size: -2, Widget: m.routes})
		}
		rows = append(rows, row)
	}
	if !m.logs.Hidden {
		rows = append(rows, layout.Row{
			Height:  -1,
			Columns: []layout.RowCell{{Title: IDLogs, Size: -1, Widget: m.logs}},
		})
	}
	if !m.help.Hidden {
		rows = append(rows, layout.Row{
			Height:  1,
			Columns: []layout.RowCell{{Title: IDHelp, Size: -1, Widget: m.help}},
		})
	}
	return layout.NewGridLayout(rows)
}

func (m *Model) buildTabOrder() *ring.Ring {
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

func (m *Model) Init() tea.Cmd {
	return tea.Batch(
		tea.RequestBackgroundColor,
	)
}

func (m *Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
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
		case key.Matches(msg, m.config.KeyMap.FocusNext):
			if m.tabOrder.Len() > 0 {
				m.tabOrder.Value.(core.Model).Blur()
				m.tabOrder = m.tabOrder.Next()
				m.tabOrder.Value.(core.Model).Focus()
				m.config.KeyMap.focusedKeyMap = m.tabOrder.Value.(core.Model).KeyMap()
			}
		case key.Matches(msg, m.config.KeyMap.FocusPrev):
			if m.tabOrder.Len() > 0 {
				m.tabOrder.Value.(core.Model).Blur()
				m.tabOrder = m.tabOrder.Prev()
				m.tabOrder.Value.(core.Model).Focus()
				m.config.KeyMap.focusedKeyMap = m.tabOrder.Value.(core.Model).KeyMap()
			}
		case key.Matches(msg, m.config.KeyMap.Quit):
			return m, tea.Quit
		case key.Matches(msg, m.config.KeyMap.ShowHidePanel):
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
			m.config.KeyMap.focusedKeyMap = nil
			m.tabOrder = m.buildTabOrder()

			if m.tabOrder.Len() > 0 {
				for r := m.tabOrder.Next(); r != m.tabOrder; r = r.Next() {
					if r.Value.(core.Model).Focused() {
						m.tabOrder = r
						break
					}
				}
				m.tabOrder.Value.(core.Model).Focus()
				m.config.KeyMap.focusedKeyMap = m.tabOrder.Value.(core.Model).KeyMap()
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
				m.config.KeyMap.modalKeyMap = nil
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
			return m, m.contextMenu.Model.Update(msg)
		case IDHeader:
			return m, m.header.Model.Update(msg)
		case IDChannels:
			m.setFocus(m.channels.Model)
			return m, m.channels.Model.Update(msg)
		case IDPermissions:
			m.setFocus(m.perms.Model)
			return m, m.perms.Model.Update(msg)
		case IDRoutes:
			m.setFocus(m.routes.Model)
			return m, m.routes.Model.Update(msg)
		case IDLogs:
			m.setFocus(m.logs.Model)
			return m, m.logs.Model.Update(msg)
		case IDHelp:
			return m, m.help.Model.Update(msg)
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
			m.logs.Model.Push(m.config.Styles.Logs.Warning.Render("warning: " + msg.GetMessage()))
			for _, hint := range msg.Hints {
				m.logs.Model.Push(m.config.Styles.Logs.Warning.Faint(true).Render("   hint: " + hint))
			}
		case extensions_ssh.Diagnostic_Error:
			m.logs.Model.Push(m.config.Styles.Logs.Error.Render("error: " + msg.GetMessage()))
			for _, hint := range msg.Hints {
				m.logs.Model.Push(m.config.Styles.Logs.Error.Faint(true).Render(" hint: " + hint))
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

func (m *Model) rebuildRouteTable() {
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

func (m *Model) rebuildPermissionsTable() {
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

func (m *Model) showContextMenu(msg menu.ShowMsg) {
	if len(msg.Entries) == 0 {
		return
	}
	m.contextMenu.Model.Reset(msg.Entries)
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
	m.config.KeyMap.modalKeyMap = m.contextMenu.Model.KeyMap()

	m.mouseMode = tea.MouseModeAllMotion
}

func (m *Model) hideContextMenu() {
	m.contextMenu.Hidden = true
	m.config.KeyMap.modalKeyMap = nil
	m.mouseMode = tea.MouseModeCellMotion
}

func (m *Model) setFocus(toFocus core.Model) {
	if toFocus.Focused() || m.tabOrder == nil {
		return
	}
	if m.tabOrder.Value.(core.Model) == toFocus {
		toFocus.Focus()
		m.config.KeyMap.focusedKeyMap = toFocus.KeyMap()
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
	m.config.KeyMap.focusedKeyMap = m.tabOrder.Value.(core.Model).KeyMap()
}

func (m *Model) resize(width int, height int) {
	m.grid.Resize(width, height)
}

func (m *Model) View() tea.View {
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

func (m *Model) newBackgroundLayer() *lipgloss.Layer {
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
