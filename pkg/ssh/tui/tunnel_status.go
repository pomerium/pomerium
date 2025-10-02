package tui

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/76creates/stickers/flexbox"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/evertras/bubble-table/table"
	zone "github.com/lrstanley/bubblezone"
	extensions_ssh "github.com/pomerium/envoy-custom/api/extensions/filters/network/ssh"
	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/pkg/ssh/portforward"
)

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
	cols := map[string]any{
		"channel":   cr.ID,
		"hostname":  cr.Hostname,
		"path":      cr.Path,
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
	channelsModel    *table.Model
	routesModel      *table.Model
	permissionsModel *table.Model
	logsModel        *LogViewerModel

	activeChannels       map[uint32]*ChannelRow
	activePortForwards   map[string]portforward.RoutePortForwardInfo
	permissionMatchCount map[*portforward.Permission]int
	allRoutes            []portforward.RouteInfo
	permissions          []*portforward.Permission

	zm *zone.Manager
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
	Align(lipgloss.Left).
	Foreground(lipgloss.Color("#ffffff"))

const (
	zoneChannels    = "channels"
	zonePermissions = "permissions"
	zoneRoutes      = "routes"
	zoneLogs        = "logs"
)

var border = table.Border{
	Top:    "─",
	Left:   "│",
	Right:  "│",
	Bottom: "─",

	TopRight:    "╮",
	TopLeft:     "╭",
	BottomRight: "╯",
	BottomLeft:  "╰",

	TopJunction:    "┬",
	LeftJunction:   "├",
	RightJunction:  "┤",
	BottomJunction: "┴",
	InnerJunction:  "┼",

	InnerDivider: "│",

	Dividers: false,
}

var headerBorder = table.Border{
	Top:    "─",
	Left:   "│",
	Right:  "│",
	Bottom: "",

	TopRight:    "╮",
	TopLeft:     "╭",
	BottomRight: "╯",
	BottomLeft:  "╰",

	TopJunction:    "─",
	LeftJunction:   "│",
	RightJunction:  "│",
	BottomJunction: "",
	InnerJunction:  "",

	InnerDivider: "",

	Dividers: false,
}

func withStyle(m *table.Model, accentColor lipgloss.TerminalColor) *table.Model {
	m.WithBaseStyle(baseStyle.BorderForeground(accentColor)).
		Border(border).
		HeaderBorder(headerBorder).
		HeaderStyle(lipgloss.NewStyle().MaxHeight(2).Bold(true).Foreground(lipgloss.Color("#ffffff"))).
		Focused(false)
	return m
}

func NewTunnelStatusModel(cfg *config.Config) *TunnelStatusModel {
	statusColors := strings.NewReplacer(
		"OPEN", textGreen.Render("OPEN"),
		"ACTIVE", textGreen.Render("ACTIVE"),
		"--", textDark.Render("--"),
		"CLOSED", textYellow.Render("CLOSED"),
	)

	m := &TunnelStatusModel{
		flexBox: flexbox.New(0, 0),
		channelsModel: withStyle(table.New([]table.Column{
			table.NewColumn("channel", "Channel", 7),
			table.NewColumn("status", "Status", 6).WithStyle(lipgloss.NewStyle().Transform(statusColors.Replace)),
			table.NewFlexColumn("hostname", "Hostname", 2),
			table.NewFlexColumn("path", "Path", 2),
			table.NewColumn("remote-ip", "Client", 21),
			table.NewFlexColumn("rx-bytes", "Rx Bytes", 1),
			table.NewFlexColumn("rx-msgs", "Rx Msgs", 1),
			table.NewFlexColumn("tx-bytes", "Tx Bytes", 1),
			table.NewFlexColumn("tx-msgs", "Tx Msgs", 1),
			table.NewFlexColumn("duration", "Duration", 1),
		}), lipgloss.ANSIColor(1)).SortByAsc("channel"),
		routesModel: withStyle(table.New([]table.Column{
			table.NewColumn("status", "Status", 7).WithStyle(lipgloss.NewStyle().Transform(statusColors.Replace)),
			table.NewFlexColumn("remote", "Remote", 1),
			table.NewFlexColumn("local", "Local", 1),
		}), lipgloss.ANSIColor(2)),
		permissionsModel: withStyle(table.New([]table.Column{
			table.NewFlexColumn("hostname", "Hostname", 1),
			table.NewColumn("port", "Port", 8).WithStyle(lipgloss.NewStyle().Transform(func(s string) string {
				if strings.HasPrefix(s, "D ") {
					return textBlue.Render(s)
				}
				return s
			})),
			table.NewColumn("match", "Routes", 7),
		}), lipgloss.ANSIColor(3)),
		logsModel: NewLogViewerModel(baseStyle.Border(lipgloss.Border{
			Top:         "─",
			Left:        "│",
			Right:       "│",
			Bottom:      "─",
			TopRight:    "╮",
			TopLeft:     "╭",
			BottomRight: "╯",
			BottomLeft:  "╰",
		}).BorderForeground(lipgloss.ANSIColor(4)), 255),
		activeChannels:       map[uint32]*ChannelRow{},
		activePortForwards:   map[string]portforward.RoutePortForwardInfo{},
		permissionMatchCount: map[*portforward.Permission]int{},
		zm:                   zone.New(),
	}

	r0c0 := flexbox.NewCell(1, 2)
	r1c0 := flexbox.NewCell(1, 2)
	r1c1 := flexbox.NewCell(2, 2)
	r2c0 := flexbox.NewCell(1, 1)

	r0c0.SetContentGenerator(func(maxX, maxY int) string {
		return m.zm.Mark(zoneChannels, m.channelsModel.WithTargetWidth(maxX).WithPageSize(maxY-6).WithMinimumHeight(maxY).View())
	})
	r1c0.SetContentGenerator(func(maxX, maxY int) string {
		return m.zm.Mark(zonePermissions, m.permissionsModel.WithTargetWidth(maxX).WithPageSize(maxY).WithMinimumHeight(maxY).View())
	})
	r1c1.SetContentGenerator(func(maxX, maxY int) string {
		return m.zm.Mark(zoneRoutes, m.routesModel.WithTargetWidth(maxX).WithPageSize(maxY).WithMinimumHeight(maxY).View())
	})
	r2c0.SetContentGenerator(func(maxX, maxY int) string {
		return m.zm.Mark(zoneLogs, m.logsModel.WithDimensions(maxX, maxY).View())
	})
	r0 := m.flexBox.NewRow().AddCells(r0c0)
	r1 := m.flexBox.NewRow().AddCells(r1c0, r1c1)
	r2 := m.flexBox.NewRow().AddCells(r2c0)
	m.flexBox.AddRows([]*flexbox.Row{r0, r1, r2})
	return m
}

func (m *TunnelStatusModel) Init() tea.Cmd { return nil }

var (
	textDark   = lipgloss.NewStyle().Foreground(lipgloss.ANSIColor(0))
	textRed    = lipgloss.NewStyle().Foreground(lipgloss.ANSIColor(1))
	textGreen  = lipgloss.NewStyle().Foreground(lipgloss.ANSIColor(2))
	textYellow = lipgloss.NewStyle().Foreground(lipgloss.ANSIColor(3))
	textBlue   = lipgloss.NewStyle().Foreground(lipgloss.ANSIColor(4))
	textBold   = lipgloss.NewStyle().Bold(true)
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
			rows = append(rows, table.NewRow(table.RowData{
				"status": status,
				"remote": fmt.Sprintf("%s:%d", route.Route.From, route.Port),
				"local":  strings.Join(to, ","),
			}))
		}
		m.routesModel = m.routesModel.WithRows(rows)
	}
	rebuildPermissionsTable := func() {
		rows := []table.Row{}
		for _, p := range m.permissions {
			sp := p.ServerPort()
			var pattern string
			if p.HostPattern.IsMatchAll() {
				pattern = "(all)"
			} else {
				pattern = p.HostPattern.InputPattern()
			}
			portStr := strconv.FormatInt(int64(sp.Value), 10)
			if sp.IsDynamic {
				portStr = "D " + portStr
			}
			rows = append(rows, table.NewRow(table.RowData{
				"hostname": pattern,
				"port":     portStr,
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
		case "q", "ctrl+c":
			return m, tea.Quit
		case "enter":

		}
	case tea.MouseMsg:
		switch msg.Action {
		case tea.MouseActionPress:
			switch msg.Button {
			case tea.MouseButtonLeft:
				m.channelsModel = m.channelsModel.Focused(m.zm.Get(zoneChannels).InBounds(msg))
				m.permissionsModel = m.permissionsModel.Focused(m.zm.Get(zonePermissions).InBounds(msg))
				m.routesModel = m.routesModel.Focused(m.zm.Get(zoneRoutes).InBounds(msg))
				m.logsModel = m.logsModel.Focused(m.zm.Get(zoneLogs).InBounds(msg))
			}
		}
	case *extensions_ssh.ChannelEvent:
		switch event := msg.Event.(type) {
		case *extensions_ssh.ChannelEvent_InternalChannelOpened:
			channelID := event.InternalChannelOpened.ChannelId
			m.activeChannels[channelID] = &ChannelRow{
				ID:          int32(channelID),
				Hostname:    event.InternalChannelOpened.Hostname,
				Path:        event.InternalChannelOpened.Path,
				Status:      "OPEN",
				PeerAddress: event.InternalChannelOpened.PeerAddress,
			}
		case *extensions_ssh.ChannelEvent_InternalChannelClosed:
			m.activeChannels[event.InternalChannelClosed.ChannelId].Status = "CLOSED"
			m.activeChannels[event.InternalChannelClosed.ChannelId].Stats = event.InternalChannelClosed.Stats
			for _, diag := range event.InternalChannelClosed.Diagnostics {
				switch diag.Severity {
				case extensions_ssh.Diagnostic_Info:
					m.logsModel.Push(diag.GetMessage())
				case extensions_ssh.Diagnostic_Error:
					m.logsModel.Push(textRed.Render("error: " + diag.GetMessage()))
					for _, hint := range diag.Hints {
						m.logsModel.Push(textRed.Faint(true).Render(" hint: " + hint))
					}
				case extensions_ssh.Diagnostic_Warning:
					m.logsModel.Push(textYellow.Render("warning: " + diag.GetMessage()))
					for _, hint := range diag.Hints {
						m.logsModel.Push(textYellow.Faint(true).Render("   hint: " + hint))
					}
				}
			}
		case *extensions_ssh.ChannelEvent_InternalChannelStats:
			m.activeChannels[event.InternalChannelStats.ChannelId].Stats = event.InternalChannelStats.Stats
		}

		rows := make([]table.Row, 0, len(m.activeChannels))
		for _, cr := range m.activeChannels {
			rows = append(rows, cr.ToRow())
		}
		m.channelsModel = m.channelsModel.WithRows(rows)
	case []portforward.RoutePortForwardInfo:
		prevNumActiveClusters := len(m.activePortForwards)
		clear(m.permissionMatchCount)
		clear(m.activePortForwards)
		for _, info := range msg {
			m.permissionMatchCount[info.Permission]++
			m.activePortForwards[info.ClusterID] = info
		}
		m.logsModel.Push(fmt.Sprintf("active route endpoints updated (%d -> %d)",
			prevNumActiveClusters, len(m.activePortForwards)))
		rebuildRouteTable()
		rebuildPermissionsTable()
	case []portforward.RouteInfo:
		m.allRoutes = msg
		rebuildRouteTable()
		m.logsModel.Push(fmt.Sprintf("routes updated (%d total)", len(msg)))
	case []*portforward.Permission:
		m.permissions = msg
		rebuildPermissionsTable()
		m.logsModel.Push(fmt.Sprintf("port-forward permissions updated (%d total)", len(msg)))
	}
	var cmd1, cmd2, cmd3, cmd4 tea.Cmd
	m.channelsModel, cmd1 = m.channelsModel.Update(msg)
	m.routesModel, cmd2 = m.routesModel.Update(msg)
	m.permissionsModel, cmd3 = m.permissionsModel.Update(msg)
	m.logsModel, cmd4 = m.logsModel.Update(msg)
	return m, tea.Batch(cmd1, cmd2, cmd3, cmd4)
}

func (m *TunnelStatusModel) View() string {
	return m.zm.Scan(m.flexBox.Render())
}
