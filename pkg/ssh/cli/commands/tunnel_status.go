package commands

import (
	"errors"
	"fmt"
	"strconv"

	"charm.land/bubbles/v2/textinput"
	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"
	uv "github.com/charmbracelet/ultraviolet"
	"github.com/muesli/termenv"
	"github.com/spf13/cobra"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/pkg/identity"
	"github.com/pomerium/pomerium/pkg/ssh/api"
	"github.com/pomerium/pomerium/pkg/ssh/cli"
	"github.com/pomerium/pomerium/pkg/ssh/models"
	"github.com/pomerium/pomerium/pkg/ssh/tui/core"
	"github.com/pomerium/pomerium/pkg/ssh/tui/preferences"
	"github.com/pomerium/pomerium/pkg/ssh/tui/style"
	"github.com/pomerium/pomerium/pkg/ssh/tui/tunnel"
	"github.com/pomerium/pomerium/pkg/ssh/tui/tunnel/components"
	"github.com/pomerium/pomerium/pkg/ssh/tui/tunnel/components/channels"
	"github.com/pomerium/pomerium/pkg/ssh/tui/tunnel/components/logs"
	"github.com/pomerium/pomerium/pkg/ssh/tui/tunnel/components/permissions"
	"github.com/pomerium/pomerium/pkg/ssh/tui/tunnel/components/routes"
	"github.com/pomerium/pomerium/pkg/ssh/tui/tunnel/messages"
	"github.com/pomerium/pomerium/pkg/ssh/tui/widgets/dialog"
	"github.com/pomerium/pomerium/pkg/ssh/tui/widgets/header"
	"github.com/pomerium/pomerium/pkg/ssh/tui/widgets/label"
	"github.com/pomerium/pomerium/pkg/ssh/tui/widgets/logviewer"
	"github.com/pomerium/pomerium/pkg/ssh/tui/widgets/menu"
	"github.com/pomerium/pomerium/pkg/ssh/tui/widgets/table"
)

const (
	ptyWidthMax  = 512
	ptyHeightMax = 512
)

func NewTunnelCommand(ic cli.InternalCLI, ctrl api.ChannelControlInterface, defaultTheme *style.Theme, prefsStore preferences.Store) *cobra.Command {
	tm := style.NewThemeManager(defaultTheme)

	cfg := tunnel.Config{
		Styles: style.Reactive(tm, tunnel.NewStyles),
		Options: tunnel.Options{
			Header: tunnel.HeaderOptions{
				LeftAlignedSegments: func(baseStyles *style.ReactiveStyles[tunnel.Styles]) []header.Segment {
					return []header.Segment{
						{
							Label:   "App Name",
							Content: func(*models.Session) string { return tunnel.AppName },
							Styles: style.Bind(baseStyles, func(base *tunnel.Styles, newStyle style.NewStyleFunc) header.SegmentStyles {
								return header.SegmentStyles{
									Base: newStyle().
										BorderStyle(style.SingleLineRoundedBorder).
										BorderLeft(true).
										BorderRight(true).
										Bold(true).
										Background(base.HeaderSegments.Colors.BrandPrimary.Normal).
										Foreground(base.HeaderSegments.Colors.BrandPrimary.ContrastingText).
										BorderForeground(base.HeaderSegments.Colors.BrandPrimary.Normal),
								}
							}),
						},
					}
				},
				RightAlignedSegments: func(baseStyles *style.ReactiveStyles[tunnel.Styles]) []header.Segment {
					return []header.Segment{
						{
							Label: "Session ID",
							Content: func(s *models.Session) string {
								if s == nil {
									return ""
								}
								return s.SessionID
							},
							Styles: style.Bind(baseStyles, func(base *tunnel.Styles, newStyle style.NewStyleFunc) header.SegmentStyles {
								return header.SegmentStyles{
									Base: newStyle().Foreground(base.HeaderSegments.Colors.TextFaint1).PaddingLeft(1).PaddingRight(1),
								}
							}),
							OnClick: func(session *models.Session, _ uv.Position) tea.Cmd {
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
							Styles: style.Bind(baseStyles, func(base *tunnel.Styles, newStyle style.NewStyleFunc) header.SegmentStyles {
								return header.SegmentStyles{
									Base: newStyle().Foreground(base.HeaderSegments.Colors.TextFaint1).PaddingLeft(1).PaddingRight(1),
								}
							}),
						},
						{
							Label: "Email",
							Content: func(s *models.Session) string {
								if s == nil {
									return ""
								}
								return s.EmailOrUserID()
							},
							OnClick: func(session *models.Session, globalPos uv.Position) tea.Cmd {
								return menu.ShowMenu(menu.Options{
									Anchor: globalPos,
									Entries: []menu.Entry{
										{
											Label: "Disconnect",
											OnSelected: func() tea.Cmd {
												return tea.Quit
											},
										},
										{
											Label: "Log Out",
											OnSelected: func() tea.Cmd {
												return dialog.ShowDialog(dialog.Options{
													Contents: core.NewWidget("", label.NewModel(label.Config{
														Options: label.Options{
															Text: fmt.Sprintf("Currently logged in as: %s",
																lipgloss.NewStyle().Bold(true).Inline(true).Render(session.EmailOrUserID())),
															HAlign: lipgloss.Center,
														},
														Styles: style.Bind(baseStyles, func(base *tunnel.Styles, _ style.NewStyleFunc) label.Styles {
															return label.Styles{Normal: base.DialogText.Padding(0, 1, 1, 1)}
														}).SetUpdateEnabled(false),
													})),
													Buttons: []dialog.ButtonConfig{
														{
															Label:   "Log Out",
															Default: true,
															OnClick: func() tea.Cmd {
																return messages.ExitWithError(cli.ErrDeleteSessionOnExit)
															},
														},
														{
															Label:   "Cancel",
															OnClick: dialog.Close,
														},
													},
													ButtonsAlignment: lipgloss.Center,
													ActionRequired:   true,
												})
											},
										},
										{
											Label: "Show User Details",
											OnSelected: func() tea.Cmd {
												info := session.Format()
												return dialog.ShowDialog(dialog.Options{
													Contents: core.NewWidget("", label.NewModel(label.Config{
														Options: label.Options{
															Text:   info,
															HAlign: lipgloss.Left,
														},
														Styles: style.Bind(baseStyles, func(base *tunnel.Styles, _ style.NewStyleFunc) label.Styles {
															return label.Styles{Normal: base.DialogText.Padding(0, 1)}
														}).SetUpdateEnabled(false),
													})),
													Buttons: []dialog.ButtonConfig{
														{
															Label:   "Close",
															Default: true,
															OnClick: dialog.Close,
														},
													},
													ButtonsAlignment: lipgloss.Center,
												})
											},
										},
									},
								})
							},
							Styles: style.Bind(baseStyles, func(base *tunnel.Styles, newStyle style.NewStyleFunc) header.SegmentStyles {
								return header.SegmentStyles{
									Base: newStyle().
										BorderStyle(style.SingleLineRoundedBorder).
										BorderLeft(true).
										BorderRight(true).
										Bold(true).
										Background(base.HeaderSegments.Colors.BrandSecondary.Normal).
										Foreground(base.HeaderSegments.Colors.BrandSecondary.ContrastingText).
										BorderForeground(base.HeaderSegments.Colors.BrandSecondary.Normal),
								}
							}),
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
			FetchMotd: func(_ models.Session) *tunnel.MotdOptions {
				// Example:
				// return &tunnel.MotdOptions{
				// 	Text:            "Important Server Message",
				// 	StartupBehavior: tunnel.ShowOnceOnStart,
				// }
				return nil
			},
		},
	}

	r := components.NewComponentFactoryRegistry()
	r.RegisterFactory(
		channels.Type,
		channels.NewComponentFactory(channels.Config{
			Styles: style.Reactive(tm, channels.DefaultStyles),
			Options: channels.Options{
				Title:  "Active Connections",
				KeyMap: table.DefaultKeyMap,
			},
		}),
	)

	r.RegisterFactory(
		permissions.Type,
		permissions.NewComponentFactory(permissions.Config{
			Styles: style.Reactive(tm, permissions.DefaultStyles),
			Options: permissions.Options{
				Title:  "Client Requests",
				KeyMap: table.DefaultKeyMap,
			},
		}),
	)

	r.RegisterFactory(
		routes.Type,
		routes.NewComponentFactory(routes.Config{
			Styles: style.Reactive(tm, routes.DefaultStyles),
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
							RequiresClipboardSupport: true,
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
										textinput.Validate = validateAddress
										return func(text string) {
											to, err := config.ParseWeightedURL(text)
											if err == nil {
												item.To = config.WeightedURLs{*to}
												ctrl.RouteDataModel().EditRoute(item)
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
		}),
	)

	r.RegisterFactory(
		logs.Type,
		logs.NewComponentFactory(logs.Config{
			Styles: style.Reactive(tm, logs.DefaultStyles),
			Options: logs.Options{
				Title:      "Logs",
				KeyMap:     logviewer.DefaultKeyMap,
				Scrollback: 256,
			},
		}),
	)

	return &cobra.Command{
		Use:    "tunnel",
		Short:  "tunnel status",
		Hidden: true,
		Annotations: map[string]string{
			"interactive": "",
		},
		RunE: func(cmd *cobra.Command, _ []string) error {
			ptyInfo := ic.PtyInfo()
			env := cli.NewSSHEnviron(ic.PtyInfo())
			session, err := ctrl.GetSession(cmd.Context())
			if err != nil {
				return fmt.Errorf("couldn't fetch session: %w", err)
			}
			prefs := prefsStore.Load(session.GetUserId())
			model := tunnel.NewTunnelStatusModel(tm, prefs, cfg, r)

			prog := tunnel.NewProgram(cmd.Context(),
				model,
				tea.WithInput(ic.Stdin()),
				tea.WithWindowSize(int(min(ic.PtyInfo().GetWidthColumns(), ptyWidthMax)), int(min(ptyInfo.GetHeightRows(), ptyHeightMax))),
				tea.WithOutput(termenv.NewOutput(ic.Stdout(), termenv.WithEnvironment(env), termenv.WithUnsafe())),
				tea.WithEnvironment(env.Environ()),
				tea.WithFPS(30),
			)

			mgr := ctrl.PortForwardManager()

			mgr.AddUpdateListener(prog)
			defer mgr.RemoveUpdateListener(prog)

			claims := identity.NewFlattenedClaimsFromPB(session.Claims)
			ic.SendTeaMsg(models.Session{
				UserID:               session.UserId,
				SessionID:            session.Id,
				Claims:               claims,
				PublicKeyFingerprint: ctrl.DownstreamPublicKeyFingerprint(),
				ClientIP:             ctrl.DownstreamSourceAddress(),
				IssuedAt:             session.IssuedAt.AsTime(),
				ExpiresAt:            session.ExpiresAt.AsTime(),
			})
			channelListener := core.NewTeaListener[models.Channel](ic)
			permissionListener := core.NewTeaListener[models.Permission](ic)
			routeListener := core.NewTeaListener[models.Route](ic)
			ctrl.ChannelDataModel().AddListener(channelListener)
			defer ctrl.ChannelDataModel().RemoveListener(channelListener)
			ctrl.PermissionDataModel().AddListener(permissionListener)
			defer ctrl.PermissionDataModel().RemoveListener(permissionListener)
			ctrl.RouteDataModel().AddListener(routeListener)
			defer ctrl.RouteDataModel().RemoveListener(routeListener)

			retModel, err := ic.RunProgram(prog.Program)
			if err != nil {
				return err
			}
			return retModel.(*tunnel.Model).Error()
		},
	}
}

func validateAddress(addr string) error {
	url, err := config.ParseWeightedURL(addr)
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
