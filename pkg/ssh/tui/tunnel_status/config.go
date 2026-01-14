package tunnel_status

import (
	"errors"
	"fmt"
	"image/color"
	"strconv"

	"charm.land/bubbles/v2/key"
	"charm.land/bubbles/v2/textinput"
	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"
	uv "github.com/charmbracelet/ultraviolet"
	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/pkg/ssh/models"
	"github.com/pomerium/pomerium/pkg/ssh/tui/style"
	"github.com/pomerium/pomerium/pkg/ssh/tui/tunnel_status/components"
	"github.com/pomerium/pomerium/pkg/ssh/tui/tunnel_status/components/channels"
	"github.com/pomerium/pomerium/pkg/ssh/tui/tunnel_status/components/logs"
	"github.com/pomerium/pomerium/pkg/ssh/tui/tunnel_status/components/permissions"
	"github.com/pomerium/pomerium/pkg/ssh/tui/tunnel_status/components/routes"
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
	BackgroundColor color.Color
	WidgetStyles
	HeaderSegments HeaderSegmentStyles
}

type WidgetStyles struct {
	Help        help.Styles
	ContextMenu menu.Styles
	Logs        LogsStyles
}

type LogsStyles struct {
	Warning lipgloss.Style
	Error   lipgloss.Style
}

type HeaderSegmentStyles struct {
	Colors style.Colors
}

type HeaderOptions struct {
	LeftAlignedSegments  func(styles HeaderSegmentStyles) []header.HeaderSegment
	RightAlignedSegments func(styles HeaderSegmentStyles) []header.HeaderSegment
}

type HelpOptions struct{}

type ContextMenuOptions struct {
	KeyMap menu.KeyMap
}

type Options struct {
	KeyMap      KeyMap
	Header      HeaderOptions
	Help        HelpOptions
	ContextMenu ContextMenuOptions
	Components  []components.Component
}

var DefaultOptions = Options{
	KeyMap: DefaultKeyMap,
	Header: HeaderOptions{
		LeftAlignedSegments: func(styles HeaderSegmentStyles) []header.HeaderSegment {
			return []header.HeaderSegment{
				{
					Label:   "App Name",
					Content: func(*models.Session) string { return AppName },
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
					Content: func(s *models.Session) string {
						if s == nil {
							return ""
						}
						return s.SessionID
					},
					Style: lipgloss.NewStyle().Foreground(lipgloss.White).Faint(true).PaddingLeft(1).PaddingRight(1),
					OnClick: func(session *models.Session, globalPos uv.Position) tea.Cmd {
						return tea.Batch(
							tea.SetClipboard(session.SessionID),
							logviewer.AddLogs("Session ID copied to clipboard"),
						)
					},
				},
				{
					Label: "Client IP",
					Content: func(s *models.Session) string {
						if s == nil {
							return ""
						}
						return s.ClientIP
					},
					Style: lipgloss.NewStyle().Foreground(lipgloss.White).Faint(true).PaddingLeft(1).PaddingRight(1),
				},
				{
					Label: "Email",
					Content: func(s *models.Session) string {
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
					OnClick: func(session *models.Session, globalPos uv.Position) tea.Cmd {
						return func() tea.Msg {
							return menu.ShowMsg{
								Anchor: globalPos,
								Entries: []menu.Entry{
									{
										Label: "Log Out",
										OnSelected: func() tea.Cmd {
											return logviewer.AddLogs("log out selected") // TODO
										},
									},
									{
										Label: "Show User Details",
										OnSelected: func() tea.Cmd {
											return logviewer.AddLogs("show user details selected") // TODO
										},
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
	Components: []components.Component{
		components.New().
			RowHint(0).
			Height(-2).
			Mnemonic("1").
			Type(channels.Type),
		components.New().
			RowHint(1).ColumnHint(0).
			Height(-2).
			Width(-1).
			Mnemonic("2").
			Type(permissions.Type),
		components.New().
			RowHint(1).ColumnHint(1).
			Height(-2).
			Width(-3).
			Mnemonic("3").
			Type(routes.Type),
		components.New().
			RowHint(2).
			Height(-1).
			Mnemonic("4").
			Type(logs.Type),
	},
	Help: HelpOptions{},
	ContextMenu: ContextMenuOptions{
		KeyMap: menu.DefaultKeyMap,
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
}

func NewStyles(theme *style.Theme) Styles {
	return Styles{
		BackgroundColor: theme.Colors.WindowBackground,
		HeaderSegments: HeaderSegmentStyles{
			Colors: theme.Colors,
		},
		WidgetStyles: WidgetStyles{
			Help:        help.NewStyles(theme),
			ContextMenu: menu.NewStyles(theme),
		},
	}
}

// Returns a new ComponentFactoryRegistry with the following built-in
// components registered:
// - 'channels' (components/channels)
// - 'permissions' (components/permissions)
// - 'routes' (components/routes)
// - 'logs' (components/logs)
func NewDefaultComponentFactoryRegistry(
	theme *style.Theme,
	channelModel *models.ChannelModel,
	permissionModel *models.PermissionModel,
	routeModel *models.RouteModel,
) components.ComponentFactoryRegistry {
	r := components.NewComponentFactoryRegistry(theme)
	r.RegisterFactory(
		channels.Type,
		channels.NewComponentFactory(channels.Config{
			Styles: channels.DefaultStyles,
			Options: channels.Options{
				Title:  "Active Connections",
				KeyMap: table.DefaultKeyMap,
				RowContextOptions: func(model *channels.TableModel, row int) []menu.Entry {
					return []menu.Entry{
						{
							Label: "Details",
							OnSelected: func() tea.Cmd {
								return logviewer.AddLogs(fmt.Sprintf("row %d: details", row)) // TODO
							},
						},
					}
				},
			},
		}, channelModel),
	)

	r.RegisterFactory(
		permissions.Type,
		permissions.NewComponentFactory(permissions.Config{
			Styles: permissions.DefaultStyles,
			Options: permissions.Options{
				Title:  "Client Requests",
				KeyMap: table.DefaultKeyMap,
				RowContextOptions: func(model *permissions.TableModel, row int) []menu.Entry {
					return []menu.Entry{
						{
							Label: "Disable",
							OnSelected: func() tea.Cmd {
								return logviewer.AddLogs(fmt.Sprintf("row %d: disable", row)) // TODO
							},
						},
					}
				},
			},
		}, permissionModel),
	)

	r.RegisterFactory(
		routes.Type,
		routes.NewComponentFactory(routes.Config{
			Styles: routes.DefaultStyles,
			Options: routes.Options{
				Title:  "Port Forward Status",
				KeyMap: table.DefaultKeyMap,
				RowContextOptions: func(model *routes.TableModel, row int) []menu.Entry {
					item := model.GetItem(row)
					entries := []menu.Entry{
						{
							Label: "Copy Remote URL",
							OnSelected: func() tea.Cmd {
								return tea.SetClipboard(item.From)
							},
						},
						{
							Label: "Disable",
							OnSelected: func() tea.Cmd {
								return logviewer.AddLogs(fmt.Sprintf("row %d: disable", row)) // TODO
							},
						},
					}
					if len(item.To) == 1 {
						entries = append(entries, menu.Entry{
							Label: "Edit Local Address",
							OnSelected: func() tea.Cmd {
								return model.Edit(row, routes.RoutesColLocal,
									func(cellContents string, textinput *textinput.Model) func(string) {
										textinput.CharLimit = 255
										textinput.Prompt = ""
										textinput.Placeholder = ""
										textinput.SetValue(cellContents)
										textinput.SetCursor(len(cellContents) + 1)
										textinput.Validate = func(text string) error {
											url, err := config.ParseWeightedURL(text)
											if err != nil {
												return err
											}
											if err := url.Validate(); err != nil {
												return err
											}
											switch url.URL.Scheme {
											case "http", "https", "h2c", "ssh":
											default:
												return errors.New("unsupported scheme")
											}
											port := url.URL.Port()
											if port == "" {
												return errors.New("port required")
											}
											if _, err := strconv.ParseUint(port, 10, 16); err != nil {
												return err
											}
											return nil
										}
										return func(text string) {
											to, err := config.ParseWeightedURL(text)
											if err == nil {
												item.To = config.WeightedURLs{*to}
												routeModel.EditRoute(item)
											}
										}
									},
								)
							},
						})
					}

					return entries
				},
			},
		}, routeModel),
	)

	r.RegisterFactory(
		logs.Type,
		logs.NewComponentFactory(logs.Config{
			Styles: logs.DefaultStyles,
			Options: logs.Options{
				Title:      "Logs",
				KeyMap:     logviewer.DefaultKeyMap,
				Scrollback: 256,
			},
		}),
	)

	return r
}
