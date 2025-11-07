package tui

import (
	"cmp"
	"context"
	"fmt"
	"maps"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/76creates/stickers/flexbox"
	"github.com/charmbracelet/bubbles/table"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	zone "github.com/lrstanley/bubblezone"
	"github.com/muesli/termenv"

	extensions_ssh "github.com/pomerium/envoy-custom/api/extensions/filters/network/ssh"
	"github.com/pomerium/pomerium/internal/hashutil"
	"github.com/pomerium/pomerium/pkg/ssh/portforward"
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
			tea.WithAltScreen(),
			tea.WithMouseCellMotion(),
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

type TunnelStatusModel struct {
	flexBox                 *flexbox.FlexBox
	channelsTableColumns    FlexColumns
	routesTableColumns      FlexColumns
	permissionsTableColumns FlexColumns
	channelsModel           table.Model
	routesModel             table.Model
	permissionsModel        table.Model
	logsModel               *LogViewerModel

	activeChannels       map[uint32]*ChannelRow
	activePortForwards   map[string]portforward.RoutePortForwardInfo
	permissionMatchCount map[uint64]int
	allRoutes            []portforward.RouteInfo
	permissions          []portforward.Permission

	zm *zone.Manager
}

const (
	zoneChannels    = "channels"
	zonePermissions = "permissions"
	zoneRoutes      = "routes"
	zoneLogs        = "logs"
)

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

type flexColumn struct {
	index  int
	weight int

	// Contains as many entries as the sum of all weights, where each entry is
	// either 0 or 1. The value is the extra width this column should have for
	// any given total (flex) width mod (sum of all weights).
	adjust []int
}

type FlexColumns struct {
	cols         []table.Column
	flexCols     []flexColumn
	fixedTotal   int
	weightsTotal int
}

// Euclid's algorithm from wikipedia
func gcd(a, b int) int {
	for b != 0 {
		t := b
		b = a % b
		a = t
	}
	return a
}

func NewFlexColumns(cols []table.Column) FlexColumns {
	var flexCols []flexColumn
	var fixedTotal int
	var weightsTotal int
	var weightsGcd int
	for i, c := range cols {
		// Negative widths are interpreted as weights. Positive widths are fixed.
		if c.Width < 0 {
			weightsTotal += -c.Width
			weightsGcd = gcd(weightsGcd, -c.Width)
			flexCols = append(flexCols, flexColumn{
				index:  i,
				weight: -c.Width,
			})
		} else {
			fixedTotal += c.Width
		}
	}

	// Divide all weights by the gcd if needed, this is otherwise 1 if the
	// weights are already simplified
	weightsTotal /= weightsGcd
	for i := range flexCols {
		flexCols[i].weight /= weightsGcd
		flexCols[i].adjust = make([]int, weightsTotal)
	}
	type flexColumnIndex struct {
		flexIndex int
		remainder float32
	}

	// After computing the integer widths for each column, we may be left with
	// remaining space to fill. The columns which had the largest fractional
	// component (i.e. would have rounded up) are given one extra width. These
	// adjustments can be precomputed since they repeat every (weightsTotal).
	for w := 1; w < weightsTotal; w++ {
		columnRemainders := make([]flexColumnIndex, len(flexCols))
		remainingUnits := w
		for i, fc := range flexCols {
			floorW := w * fc.weight / weightsTotal
			remainingUnits -= floorW
			columnRemainders[i] = flexColumnIndex{
				flexIndex: i,
				remainder: (float32(w) * float32(fc.weight) / float32(weightsTotal)) - float32(floorW),
			}
		}
		// stable sort columns descending by remainder
		slices.SortStableFunc(columnRemainders, func(a, b flexColumnIndex) int {
			return cmp.Compare(b.remainder, a.remainder)
		})
		// add 1 to the first remainingUnits columns with the highest remainders
		// for this value of w
		for i := range remainingUnits {
			flexCols[columnRemainders[i].flexIndex].adjust[w] = 1
		}
	}

	return FlexColumns{
		cols:         cols,
		flexCols:     flexCols,
		weightsTotal: weightsTotal,
		fixedTotal:   fixedTotal,
	}
}

func (fc *FlexColumns) Resized(width int) []table.Column {
	width = max(0, width-fc.fixedTotal-len(fc.cols))
	w := width % fc.weightsTotal
	for _, col := range fc.flexCols {
		fc.cols[col.index].Width = width*col.weight/fc.weightsTotal + col.adjust[w]
	}
	return fc.cols
}

func tableStyle() table.Styles {
	whiteFgStart := termenv.CSI + lipgloss.DefaultRenderer().ColorProfile().Color("#ffffff").Sequence(false) + "m"
	greenFgStart := termenv.CSI + lipgloss.DefaultRenderer().ColorProfile().Color("2").Sequence(false) + "m"
	yellowFgStart := termenv.CSI + lipgloss.DefaultRenderer().ColorProfile().Color("3").Sequence(false) + "m"
	blueFgStart := termenv.CSI + lipgloss.DefaultRenderer().ColorProfile().Color("4").Sequence(false) + "m"
	darkFgStart := termenv.CSI + lipgloss.DefaultRenderer().ColorProfile().Color("0").Sequence(false) + "m"

	statusColors := strings.NewReplacer(
		"OPEN", greenFgStart+"OPEN"+whiteFgStart,
		"ACTIVE", greenFgStart+"ACTIVE"+whiteFgStart,
		"--", darkFgStart+"--"+whiteFgStart,
		"CLOSED", yellowFgStart+"CLOSED"+whiteFgStart,
	)

	return table.Styles{
		Selected: lipgloss.NewStyle().Bold(true).Background(lipgloss.ANSIColor(8)).Foreground(lipgloss.Color("#ffffff")),
		Header:   lipgloss.NewStyle().Bold(true).PaddingLeft(1),
		Cell: lipgloss.NewStyle().PaddingLeft(1).Transform(func(s string) string {
			if strings.HasPrefix(s, "D ") {
				return blueFgStart + s + whiteFgStart
			}
			return statusColors.Replace(s)
		}),
	}
}

const (
	channelsAccentColor    = lipgloss.ANSIColor(1)
	routesAccentColor      = lipgloss.ANSIColor(2)
	permissionsAccentColor = lipgloss.ANSIColor(3)
	logsAccentColor        = lipgloss.ANSIColor(4)
)

func NewTunnelStatusModel() *TunnelStatusModel {
	m := &TunnelStatusModel{
		flexBox: flexbox.New(0, 0),
		channelsTableColumns: NewFlexColumns([]table.Column{
			{Title: "Channel", Width: 7},
			{Title: "Status", Width: 6},
			{Title: "Hostname", Width: -2},
			{Title: "Path", Width: -2},
			{Title: "Client", Width: 21},
			{Title: "Rx Bytes", Width: -1},
			{Title: "Tx Bytes", Width: -1},
			{Title: "Duration", Width: -1},
		}),
		routesTableColumns: NewFlexColumns([]table.Column{
			{Title: "Status", Width: 7},
			{Title: "Remote", Width: -1},
			{Title: "Local", Width: -1},
		}),
		permissionsTableColumns: NewFlexColumns([]table.Column{
			{Title: "Hostname", Width: -1},
			{Title: "Port", Width: 8},
			{Title: "Routes", Width: 7},
		}),
		channelsModel:        table.New(table.WithStyles(tableStyle()), table.WithFocused(false)),
		routesModel:          table.New(table.WithStyles(tableStyle()), table.WithFocused(false)),
		permissionsModel:     table.New(table.WithStyles(tableStyle()), table.WithFocused(false)),
		logsModel:            NewLogViewerModel(lipgloss.NewStyle().Align(lipgloss.Left).Border(border).BorderForeground(logsAccentColor), 255),
		activeChannels:       map[uint32]*ChannelRow{},
		activePortForwards:   map[string]portforward.RoutePortForwardInfo{},
		permissionMatchCount: map[uint64]int{},
		zm:                   zone.New(),
	}

	r0c0 := flexbox.NewCell(1, 2)
	r1c0 := flexbox.NewCell(1, 2)
	r1c1 := flexbox.NewCell(2, 2)
	r2c0 := flexbox.NewCell(1, 1)

	r0c0.SetContentGenerator(func(maxX, maxY int) string {
		m.channelsModel.SetWidth(max(maxX-2, 0))
		m.channelsModel.SetHeight(max(maxY-2, 0))
		m.channelsModel.SetColumns(m.channelsTableColumns.Resized(m.channelsModel.Width()))

		return m.zm.Mark(zoneChannels, lipgloss.NewStyle().Border(border).BorderForeground(channelsAccentColor).Render(m.channelsModel.View()))
	})
	r1c0.SetContentGenerator(func(maxX, maxY int) string {
		m.permissionsModel.SetWidth(max(maxX-2, 0))
		m.permissionsModel.SetHeight(max(maxY-2, 0))
		m.permissionsModel.SetColumns(m.permissionsTableColumns.Resized(m.permissionsModel.Width()))

		return m.zm.Mark(zonePermissions, lipgloss.NewStyle().Border(border).BorderForeground(permissionsAccentColor).Render(m.permissionsModel.View()))
	})
	r1c1.SetContentGenerator(func(maxX, maxY int) string {
		m.routesModel.SetWidth(max(maxX-2, 0))
		m.routesModel.SetHeight(max(maxY-2, 0))
		m.routesModel.SetColumns(m.routesTableColumns.Resized(m.routesModel.Width()))

		return m.zm.Mark(zoneRoutes, lipgloss.NewStyle().Border(border).BorderForeground(routesAccentColor).Render(m.routesModel.View()))
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
	textRed    = lipgloss.NewStyle().Foreground(lipgloss.ANSIColor(1))
	textYellow = lipgloss.NewStyle().Foreground(lipgloss.ANSIColor(3))
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
		m.routesModel.SetRows(rows)
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
		m.permissionsModel.SetRows(rows)
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
				if m.zm.Get(zoneChannels).InBounds(msg) {
					m.channelsModel.Focus()
				} else {
					m.channelsModel.Blur()
				}
				if m.zm.Get(zonePermissions).InBounds(msg) {
					m.permissionsModel.Focus()
				} else {
					m.permissionsModel.Blur()
				}
				if m.zm.Get(zoneRoutes).InBounds(msg) {
					m.routesModel.Focus()
				} else {
					m.routesModel.Blur()
				}
				m.logsModel = m.logsModel.Focused(m.zm.Get(zoneLogs).InBounds(msg))
			}
		}
	case *extensions_ssh.ChannelEvent:
		switch event := msg.Event.(type) {
		case *extensions_ssh.ChannelEvent_InternalChannelOpened:
			channelID := event.InternalChannelOpened.ChannelId
			m.activeChannels[channelID] = &ChannelRow{
				ID:          int32(channelID),
				Status:      "OPEN",
				Hostname:    event.InternalChannelOpened.Hostname,
				Path:        event.InternalChannelOpened.Path,
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
		case *extensions_ssh.ChannelEvent_ChannelStats:
			for _, entry := range event.ChannelStats.GetStatsList().GetItems() {
				if ch, ok := m.activeChannels[entry.ChannelId]; ok {
					ch.Stats = entry
				}
			}
		}

		rows := make([]table.Row, 0, len(m.activeChannels))
		for _, cr := range m.activeChannels {
			rows = append(rows, cr.ToRow())
		}
		m.channelsModel.SetRows(rows)
	case map[string]portforward.RoutePortForwardInfo:
		prevNumActiveClusters := len(m.activePortForwards)
		clear(m.permissionMatchCount)
		clear(m.activePortForwards)
		for clusterID, info := range msg {
			m.permissionMatchCount[permissionHash(info.Permission)]++
			m.activePortForwards[clusterID] = info
		}
		m.logsModel.Push(fmt.Sprintf("active route endpoints updated (%d -> %d)",
			prevNumActiveClusters, len(m.activePortForwards)))
		rebuildRouteTable()
		rebuildPermissionsTable()
	case []portforward.RouteInfo:
		m.allRoutes = msg
		rebuildRouteTable()
		m.logsModel.Push(fmt.Sprintf("routes updated (%d total)", len(msg)))
	case []portforward.Permission:
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

func permissionHash(p portforward.Permission) uint64 {
	d := hashutil.NewDigest()
	d.WriteStringWithLen(p.HostMatcher.InputPattern())
	d.WriteUint32(p.RequestedPort)
	d.WriteUint32(uint32(p.VirtualPort))
	return d.Sum64()
}
