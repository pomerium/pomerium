package tui

import (
	"strconv"
	"strings"
	"time"

	"github.com/76creates/stickers/flexbox"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/evertras/bubble-table/table"
	extensions_ssh "github.com/pomerium/envoy-custom/api/extensions/filters/network/ssh"
	"github.com/pomerium/pomerium/pkg/ssh/portforward"
)

type channelRow struct {
	ID          int32
	Status      string
	PeerAddress string
	Stats       *extensions_ssh.ChannelEvent_InternalChannelClosedEvent_Stats
}

func (cr *channelRow) ToRow() table.Row {
	cols := map[string]any{
		"channel":   cr.ID,
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
	flexBox        *flexbox.FlexBox
	requests       table.Model
	activeChannels map[uint32]*channelRow

	routes table.Model
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

func NewTunnelStatusModel() TunnelStatusModel {
	m := TunnelStatusModel{
		flexBox: flexbox.New(0, 0),
		requests: table.New([]table.Column{
			table.NewColumn("channel", "Channel", 7),
			table.NewColumn("status", "Status", 6),
			table.NewColumn("remote-ip", "Remote IP", 21),
			table.NewFlexColumn("rx-bytes", "Rx Bytes", 1),
			table.NewFlexColumn("rx-msgs", "Rx Msgs", 1),
			table.NewFlexColumn("tx-bytes", "Tx Bytes", 1),
			table.NewFlexColumn("tx-msgs", "Tx Msgs", 1),
			table.NewFlexColumn("duration", "Duration", 1),
		}).SelectableRows(false).Focused(false).SortByAsc("channel").WithMissingDataIndicator("--"),
		routes: table.New([]table.Column{
			table.NewColumn("protocol", "Protocol", 9),
			table.NewFlexColumn("remote", "Remote", 1),
			table.NewFlexColumn("local", "Local", 1),
		}).SelectableRows(false).Focused(false),
		activeChannels: map[uint32]*channelRow{},
	}
	r1 := m.flexBox.NewRow().AddCells(flexbox.NewCell(1, 1))
	r2 := m.flexBox.NewRow().AddCells(flexbox.NewCell(1, 1))
	m.flexBox.AddRows([]*flexbox.Row{r1, r2})
	return m
}

func (m TunnelStatusModel) Init() tea.Cmd { return nil }

func (m TunnelStatusModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
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
			m.activeChannels[channelID] = &channelRow{
				ID:          int32(channelID),
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
		m.requests = m.requests.WithRows(rows)
	case []portforward.RoutePortForwardInfo:
		rows := []table.Row{}
		for _, info := range msg {
			to, _, _ := info.Route.To.Flatten()

			var protocol string
			switch {
			case strings.HasPrefix(info.Route.From, "https://"):
				protocol = "HTTPS"
			case strings.HasPrefix(info.Route.From, "ssh://"):
				protocol = "SSH"
			}
			rows = append(rows, table.NewRow(table.RowData{
				"protocol": protocol,
				"remote":   info.Hostname,
				"local":    strings.Join(to, ","),
			}))
		}
		m.routes = m.routes.WithRows(rows)
	}
	var cmd1, cmd2 tea.Cmd
	m.requests, cmd1 = m.requests.Update(msg)
	m.routes, cmd2 = m.routes.Update(msg)
	return m, tea.Batch(cmd1, cmd2)
}

func (m TunnelStatusModel) View() string {
	m.flexBox.ForceRecalculate()
	r1 := m.flexBox.GetRow(0).GetCell(0)
	r2 := m.flexBox.GetRow(1).GetCell(0)
	r1.SetContent(m.requests.WithTargetWidth(r1.GetWidth()).WithPageSize(r1.GetHeight() - 1).View())
	r2.SetContent(m.routes.WithTargetWidth(r2.GetWidth()).WithPageSize(r2.GetHeight() - 1).View())
	return m.flexBox.Render()
}
