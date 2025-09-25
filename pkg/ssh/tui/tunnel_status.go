package tui

import (
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/76creates/stickers/flexbox"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/evertras/bubble-table/table"
	extensions_ssh "github.com/pomerium/envoy-custom/api/extensions/filters/network/ssh"
	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/pkg/ssh/portforward"
)

type ChannelRow struct {
	ID          int32
	Hostname    string
	Status      string
	PeerAddress string
	Stats       *extensions_ssh.ChannelEvent_InternalChannelClosedEvent_Stats
}

func (cr *ChannelRow) ToRow() table.Row {
	cols := map[string]any{
		"channel":   cr.ID,
		"hostname":  cr.Hostname,
		"status":    cr.Status,
		"remote-ip": cr.PeerAddress,
	}

	if cr.Stats != nil {
		cols["rx-bytes"] = strconv.FormatUint(cr.Stats.RxBytesTotal, 10)
		cols["rx-msgs"] = strconv.FormatUint(cr.Stats.RxPacketsTotal, 10)
		cols["tx-bytes"] = strconv.FormatUint(cr.Stats.TxBytesTotal, 10)
		cols["tx-msgs"] = strconv.FormatUint(cr.Stats.TxPacketsTotal, 10)
		cols["duration"] = cr.Stats.ChannelDuration.AsDuration().Round(time.Millisecond).String()
	}
	return table.NewRow(cols)
}

type TunnelStatusModel struct {
	flexBox          *flexbox.FlexBox
	channelsModel    table.Model
	routesModel      table.Model
	permissionsModel table.Model

	activeChannels       map[uint32]*ChannelRow
	activePortForwards   map[string]portforward.RoutePortForwardInfo
	permissionMatchCount map[*portforward.Permission]int
	allRoutes            []portforward.RouteInfo
	permissions          []*portforward.Permission

	defaultHttpPort string
	defaultSshPort  string
}

var (
	tableDefaultHeaderStyle = lipgloss.NewStyle().
				Background(lipgloss.Color("#7c3aed")).
				Foreground(lipgloss.Color("#ffffff"))
	tableDefaultFooterStyle = tableDefaultHeaderStyle.Align(lipgloss.Right).Height(1)
	tableDefaultRowsStyle   = lipgloss.NewStyle().
				Background(lipgloss.Color("#262626")).
				Foreground(lipgloss.Color("#ffffff"))
	tableDefaultRowsSubsequentStyle = lipgloss.NewStyle().
					Background(lipgloss.Color("#2a2a2b")).
					Foreground(lipgloss.Color("#ffffff"))
)

var baseStyle = lipgloss.NewStyle().
	Align(lipgloss.Left)

func NewTunnelStatusModel(cfg *config.Config) *TunnelStatusModel {
	m := &TunnelStatusModel{
		flexBox: flexbox.New(0, 0),
		channelsModel: table.New([]table.Column{
			table.NewColumn("channel", "Channel", 7),
			table.NewColumn("status", "Status", 6),
			table.NewFlexColumn("hostname", "Route Hostname", 3),
			table.NewColumn("remote-ip", "Remote IP", 21),
			table.NewFlexColumn("rx-bytes", "Rx Bytes", 1),
			table.NewFlexColumn("rx-msgs", "Rx Msgs", 1),
			table.NewFlexColumn("tx-bytes", "Tx Bytes", 1),
			table.NewFlexColumn("tx-msgs", "Tx Msgs", 1),
			table.NewFlexColumn("duration", "Duration", 1),
		}).
			WithBaseStyle(baseStyle).
			BorderRounded().
			SelectableRows(false).
			Focused(false).
			SortByAsc("channel"),
		routesModel: table.New([]table.Column{
			table.NewColumn("status", "Status", 7),
			table.NewFlexColumn("remote", "Remote", 1),
			table.NewFlexColumn("local", "Local", 1),
		}).
			WithBaseStyle(baseStyle).
			BorderRounded().
			SelectableRows(false).
			Focused(false),
		activeChannels: map[uint32]*ChannelRow{},
		permissionsModel: table.New([]table.Column{
			table.NewFlexColumn("hostname", "Hostname", 1),
			table.NewColumn("port", "Port", 7),
			table.NewColumn("match", "Routes", 7),
		}).
			WithBaseStyle(baseStyle).
			BorderRounded().
			SelectableRows(false).
			Focused(false),
		activePortForwards:   map[string]portforward.RoutePortForwardInfo{},
		permissionMatchCount: map[*portforward.Permission]int{},
	}
	_, m.defaultHttpPort, _ = net.SplitHostPort(cfg.Options.Addr)
	_, m.defaultSshPort, _ = net.SplitHostPort(cfg.Options.SSHAddr)
	if m.defaultHttpPort == "" {
		m.defaultHttpPort = "443"
	}
	if m.defaultSshPort == "" {
		m.defaultSshPort = "22"
	}

	r0c0 := flexbox.NewCell(1, 1)
	r1c0 := flexbox.NewCell(1, 1)
	r1c1 := flexbox.NewCell(2, 1)
	r0c0.SetContentGenerator(func(maxX, maxY int) string {
		return m.channelsModel.WithTargetWidth(maxX).WithPageSize(maxY).WithMinimumHeight(maxY).View()
	})
	r1c0.SetContentGenerator(func(maxX, maxY int) string {
		return m.permissionsModel.WithTargetWidth(maxX).WithPageSize(maxY).WithMinimumHeight(maxY).View()
	})
	r1c1.SetContentGenerator(func(maxX, maxY int) string {
		return m.routesModel.WithTargetWidth(maxX).WithPageSize(maxY).WithMinimumHeight(maxY).View()
	})
	r1 := m.flexBox.NewRow().AddCells(r0c0)
	r2 := m.flexBox.NewRow().AddCells(r1c0, r1c1)
	m.flexBox.AddRows([]*flexbox.Row{r1, r2})
	return m
}

func (m *TunnelStatusModel) Init() tea.Cmd { return nil }

func (m *TunnelStatusModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	rebuildRouteTable := func() {
		rows := []table.Row{}
		for _, route := range m.allRoutes {
			status := "--"
			if _, ok := m.activePortForwards[route.ClusterID]; ok {
				status = "ACTIVE"
			}
			to, _, _ := route.Route.To.Flatten()
			var port string
			if strings.HasPrefix(route.Route.From, "https://") {
				port = ":" + m.defaultHttpPort
			} else if strings.HasPrefix(route.Route.From, "ssh://") {
				port = ":" + m.defaultSshPort
			}
			rows = append(rows, table.NewRow(table.RowData{
				"status": status,
				"remote": route.Route.From + port,
				"local":  strings.Join(to, ","),
			}))
		}
		m.routesModel = m.routesModel.WithRows(rows)
	}
	rebuildPermissionsTable := func() {
		rows := []table.Row{}
		for _, p := range m.permissions {
			sp := p.ServerPort()
			pattern := p.HostPattern.InputPattern()
			if pattern == "" {
				pattern = "(all)"
			}
			rows = append(rows, table.NewRow(table.RowData{
				"hostname": pattern,
				"port":     sp.Value,
				"match":    m.permissionMatchCount[p],
			}))
		}
		m.permissionsModel = m.permissionsModel.WithRows(rows)
	}
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.flexBox.SetHeight(msg.Height)
		m.flexBox.SetWidth(msg.Width)
	case tea.KeyMsg:
		switch msg.String() {
		// case "esc":
		// 	if m.table.Focused() {
		// 		m.table.Blur()
		// 	} else {
		// 		m.table.Focus()
		// 	}
		case "q", "ctrl+c":
			return m, tea.Quit
		case "enter":

		}
	case *extensions_ssh.ChannelEvent:
		switch event := msg.Event.(type) {
		case *extensions_ssh.ChannelEvent_InternalChannelOpened:
			channelID := event.InternalChannelOpened.ChannelId
			m.activeChannels[channelID] = &ChannelRow{
				ID:          int32(channelID),
				Hostname:    event.InternalChannelOpened.Hostname,
				Status:      "OPEN",
				PeerAddress: event.InternalChannelOpened.PeerAddress,
			}
		case *extensions_ssh.ChannelEvent_InternalChannelClosed:
			m.activeChannels[event.InternalChannelClosed.ChannelId].Status = "CLOSED"
			m.activeChannels[event.InternalChannelClosed.ChannelId].Stats = event.InternalChannelClosed.Stats
		}

		rows := make([]table.Row, 0, len(m.activeChannels))
		for _, cr := range m.activeChannels {
			rows = append(rows, cr.ToRow())
		}
		m.channelsModel = m.channelsModel.WithRows(rows)
	case []portforward.RoutePortForwardInfo:
		clear(m.permissionMatchCount)
		clear(m.activePortForwards)
		for _, info := range msg {
			m.permissionMatchCount[info.Permission]++
			m.activePortForwards[info.ClusterID] = info
		}
		rebuildRouteTable()
		rebuildPermissionsTable()
	case []portforward.RouteInfo:
		m.allRoutes = msg
		rebuildRouteTable()
	case []*portforward.Permission:
		m.permissions = msg
		rebuildPermissionsTable()
	}
	var cmd1, cmd2, cmd3 tea.Cmd
	m.channelsModel, cmd1 = m.channelsModel.Update(msg)
	m.routesModel, cmd2 = m.routesModel.Update(msg)
	m.permissionsModel, cmd3 = m.permissionsModel.Update(msg)
	return m, tea.Batch(cmd1, cmd2, cmd3)
}

func (m *TunnelStatusModel) View() string {
	return m.flexBox.Render()
}
