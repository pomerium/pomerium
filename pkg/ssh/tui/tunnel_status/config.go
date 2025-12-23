package tunnel_status

import (
	"fmt"
	"strings"

	"charm.land/bubbles/v2/key"
	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"
	uv "github.com/charmbracelet/ultraviolet"
	"github.com/pomerium/pomerium/pkg/ssh/model"
	"github.com/pomerium/pomerium/pkg/ssh/tui/style"
	"github.com/pomerium/pomerium/pkg/ssh/tui/widgets/header"
	"github.com/pomerium/pomerium/pkg/ssh/tui/widgets/help"
	"github.com/pomerium/pomerium/pkg/ssh/tui/widgets/logviewer"
	"github.com/pomerium/pomerium/pkg/ssh/tui/widgets/menu"
	"github.com/pomerium/pomerium/pkg/ssh/tui/widgets/table"
)

type Config struct {
	Styles Styles
	Options
}

type Styles struct {
	WidgetStyles
	HeaderSegments HeaderSegmentStyles
}

type TableStyles struct {
	table.Styles
	ColumnStyles map[string]func(s string) lipgloss.Style
}

type LogViewerStyles struct {
	logviewer.Styles
	Warning lipgloss.Style
	Error   lipgloss.Style
}

type WidgetStyles struct {
	Channels    TableStyles
	Permissions TableStyles
	Routes      TableStyles
	Logs        LogViewerStyles
	Help        help.Styles
	ContextMenu menu.Styles
}

type HeaderSegmentStyles struct {
	Colors style.Colors
}

type WidgetOptions struct {
	Header      HeaderOptions
	Channels    ChannelsOptions
	Permissions PermissionsOptions
	Routes      RoutesOptions
	Logs        LogsOptions
	Help        HelpOptions
	ContextMenu ContextMenuOptions
}

type HeaderOptions struct {
	Hide                 bool
	LeftAlignedSegments  func(styles HeaderSegmentStyles) []header.HeaderSegment
	RightAlignedSegments func(styles HeaderSegmentStyles) []header.HeaderSegment
}

type ChannelsOptions struct {
	StartHidden       bool
	Title             string
	KeyMap            table.KeyMap
	RowContextOptions func(model *table.Model, row int) []menu.Entry
}

type PermissionsOptions struct {
	StartHidden       bool
	Title             string
	KeyMap            table.KeyMap
	RowContextOptions func(model *table.Model, row int) []menu.Entry
	ColumnStyles      map[string]func(s string) lipgloss.Style
}

type RoutesOptions struct {
	StartHidden       bool
	Title             string
	KeyMap            table.KeyMap
	RowContextOptions func(model *table.Model, row int) []menu.Entry
	ColumnStyles      map[string]func(s string) lipgloss.Style
}

type LogsOptions struct {
	StartHidden bool
	Title       string
	KeyMap      logviewer.KeyMap
	Scrollback  int
}

type HelpOptions struct {
	Hide bool
}

type ContextMenuOptions struct {
	KeyMap menu.KeyMap
}

type Options struct {
	WidgetOptions
	KeyMap KeyMap
}

var DefaultOptions = Options{
	KeyMap: DefaultKeyMap,
	WidgetOptions: WidgetOptions{
		Header: HeaderOptions{
			Hide: false,
			LeftAlignedSegments: func(styles HeaderSegmentStyles) []header.HeaderSegment {
				return []header.HeaderSegment{
					{
						Label:   "App Name",
						Content: func(*model.Session) string { return AppName },
						Style: lipgloss.NewStyle().
							BorderStyle(style.SingleLineRoundedBorder).
							BorderLeft(true).
							BorderRight(true).
							Bold(true).
							Background(styles.Colors.BrandPrimary.Normal).
							Foreground(styles.Colors.BrandPrimary.ContrastingText).
							BorderForeground(styles.Colors.BrandPrimary.Normal),
					},
				}
			},
			RightAlignedSegments: func(styles HeaderSegmentStyles) []header.HeaderSegment {
				return []header.HeaderSegment{
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
						OnClick: func(globalPos uv.Position) tea.Cmd {
							return func() tea.Msg {
								return menu.ShowMsg{
									Anchor: globalPos,
									Entries: []menu.Entry{
										{
											Label:      "Log Out",
											OnSelected: logviewer.AddLog("log out selected"), // TODO
										},
										{
											Label:      "Show User Details",
											OnSelected: logviewer.AddLog("show user details selected"), // TODO
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
							Background(styles.Colors.BrandSecondary.Normal).
							Foreground(styles.Colors.BrandSecondary.ContrastingText).
							BorderForeground(styles.Colors.BrandSecondary.Normal),
					},
				}
			},
		},
		Channels: ChannelsOptions{
			StartHidden: false,
			Title:       "Active Connections",
			KeyMap:      table.DefaultKeyMap,
			RowContextOptions: func(model *table.Model, row int) []menu.Entry {
				return []menu.Entry{
					{
						Label:      "Details",
						OnSelected: logviewer.AddLog(fmt.Sprintf("row %d: details", row)), // TODO
					},
				}
			},
		},
		Permissions: PermissionsOptions{
			StartHidden: false,
			Title:       "Client Requests",
			KeyMap:      table.DefaultKeyMap,
			RowContextOptions: func(model *table.Model, row int) []menu.Entry {
				return []menu.Entry{
					{
						Label:      "Disable",
						OnSelected: logviewer.AddLog(fmt.Sprintf("row %d: disable", row)), // TODO
					},
				}
			},
			ColumnStyles: map[string]func(s string) lipgloss.Style{},
		},
		Routes: RoutesOptions{
			StartHidden: false,
			Title:       "Port Forward Status",
			KeyMap:      table.DefaultKeyMap,
			RowContextOptions: func(model *table.Model, row int) []menu.Entry {
				return []menu.Entry{
					{
						Label:      "Disable",
						OnSelected: logviewer.AddLog(fmt.Sprintf("row %d: disable", row)), // TODO
					},
					{
						Label:      "Edit Local Port",
						OnSelected: logviewer.AddLog(fmt.Sprintf("row %d: edit local port", row)), // TODO
					},
				}
			},
			ColumnStyles: map[string]func(s string) lipgloss.Style{},
		},
		Logs: LogsOptions{
			StartHidden: false,
			Title:       "Logs",
			KeyMap:      logviewer.DefaultKeyMap,
			Scrollback:  256,
		},
		Help: HelpOptions{
			Hide: false,
		},
		ContextMenu: ContextMenuOptions{
			KeyMap: menu.DefaultKeyMap,
		},
	},
}

var DefaultKeyMap = KeyMap{
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
}

func NewStyles(theme *style.Theme) Styles {
	return Styles{
		HeaderSegments: HeaderSegmentStyles{
			Colors: theme.Colors,
		},
		WidgetStyles: WidgetStyles{
			Channels: TableStyles{
				Styles: table.NewStyles(theme, theme.Colors.Accent1),
				ColumnStyles: map[string]func(s string) lipgloss.Style{
					"Status": func(s string) lipgloss.Style {
						switch s {
						case "OPEN":
							return theme.TextStatusHealthy
						case "CLOSED":
							return theme.TextStatusDegraded
						default:
							return lipgloss.Style{}
						}
					},
					"Client": func(s string) lipgloss.Style {
						if s == "envoy_health_check" {
							return lipgloss.NewStyle().
								Faint(true).
								Transform(func(string) string { return "Health Check" })
						}
						return lipgloss.Style{}
					},
				},
			},
			Permissions: TableStyles{
				Styles: table.NewStyles(theme, theme.Colors.Accent2),
				ColumnStyles: map[string]func(s string) lipgloss.Style{
					"Hostname": func(s string) lipgloss.Style {
						if s == "(all)" {
							return lipgloss.NewStyle().Faint(true)
						}
						return lipgloss.Style{}
					},
					"Port": func(s string) lipgloss.Style {
						if strings.HasPrefix(s, "D ") {
							return lipgloss.NewStyle().Foreground(lipgloss.Blue)
						}
						return lipgloss.Style{}
					},
				},
			},
			Routes: TableStyles{
				Styles: table.NewStyles(theme, theme.Colors.Accent3),
				ColumnStyles: map[string]func(s string) lipgloss.Style{
					"Status": func(s string) lipgloss.Style {
						switch s {
						case "ACTIVE":
							return theme.TextStatusHealthy
						case "INACTIVE":
							return theme.TextStatusUnknown
						case "--":
							return theme.TextStatusUnknown
						default:
							return lipgloss.Style{}
						}
					},
					"Health": func(s string) lipgloss.Style {
						switch s {
						case "HEALTHY":
							return theme.TextStatusHealthy
						case "UNHEALTHY", "ERROR":
							return theme.TextStatusUnhealthy
						case "DEGRADED":
							return theme.TextStatusDegraded
						case "UNKNOWN", "--":
							return theme.TextStatusUnknown
						default:
							return lipgloss.Style{}
						}
					},
				},
			},
			Logs: LogViewerStyles{
				Styles:  logviewer.NewStyles(theme, theme.Colors.Accent4),
				Warning: theme.TextWarning,
				Error:   theme.TextError,
			},
			Help:        help.NewStyles(theme),
			ContextMenu: menu.NewStyles(theme),
		},
	}
}
