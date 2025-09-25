package ssh

import (
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/charmbracelet/bubbles/list"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/pomerium/envoy-custom/api/extensions/filters/network/ssh"
	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/pkg/ssh/tui"
	"github.com/spf13/cobra"
)

type CLI struct {
	*cobra.Command
	tui      *tea.Program
	msgQueue chan tea.Msg
	ptyInfo  *ssh.SSHDownstreamPTYInfo
	username string
}

func NewCLI(
	cfg *config.Config,
	ctrl ChannelControlInterface,
	ptyInfo *ssh.SSHDownstreamPTYInfo,
	stdin io.Reader,
	stdout io.Writer,
) *CLI {
	cmd := &cobra.Command{
		Use: "pomerium",
		PersistentPreRunE: func(cmd *cobra.Command, _ []string) error {
			_, cmdIsInteractive := cmd.Annotations["interactive"]
			switch {
			case (ptyInfo == nil) && cmdIsInteractive:
				return fmt.Errorf("\x1b[31m'%s' is an interactive command and requires a TTY (try passing '-t' to ssh)\x1b[0m", cmd.Use)
			case (ptyInfo != nil) && !cmdIsInteractive:
				return fmt.Errorf("\x1b[31m'%s' is not an interactive command (try passing '-T' to ssh, or removing '-t')\x1b[0m\r", cmd.Use)
			}
			return nil
		},
	}

	cmd.CompletionOptions.DisableDefaultCmd = true
	// set a non-nil args list, otherwise it will read from os.Args by default
	cmd.SetArgs([]string{})
	cmd.SetIn(stdin)
	cmd.SetOut(stdout)
	cmd.SetErr(stdout)
	cmd.SilenceUsage = true

	cli := &CLI{
		Command:  cmd,
		tui:      nil,
		msgQueue: make(chan tea.Msg, 8),
		ptyInfo:  ptyInfo,
		username: *ctrl.Username(),
	}

	if cfg.Options.IsRuntimeFlagSet(config.RuntimeFlagSSHRoutesPortal) {
		cli.AddPortalCommand(ctrl)
	}
	cli.AddTunnelCommand(ctrl)
	cli.AddLogoutCommand(ctrl)
	cli.AddWhoamiCommand(ctrl)

	return cli
}

func (cli *CLI) AddLogoutCommand(_ ChannelControlInterface) {
	cli.AddCommand(&cobra.Command{
		Use:           "logout",
		Short:         "Log out",
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			_, _ = cmd.OutOrStdout().Write([]byte("Logged out successfully\r\n"))
			return ErrDeleteSessionOnExit
		},
	})
}

func (cli *CLI) AddWhoamiCommand(ctrl ChannelControlInterface) {
	cli.AddCommand(&cobra.Command{
		Use:   "whoami",
		Short: "Show details for the current session",
		RunE: func(cmd *cobra.Command, _ []string) error {
			s, err := ctrl.FormatSession(cmd.Context())
			if err != nil {
				return fmt.Errorf("couldn't fetch session: %w\r", err)
			}
			_, _ = cmd.OutOrStdout().Write(s)
			return nil
		},
	})
}

func (cli *CLI) AddTunnelCommand(ctrl ChannelControlInterface) {
	cli.AddCommand(&cobra.Command{
		Use:    "tunnel",
		Short:  "tunnel status",
		Hidden: true,
		Annotations: map[string]string{
			"interactive": "",
		},
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			model := tui.NewTunnelStatusModel()

			cli.SendTeaMsg(tea.WindowSizeMsg{Width: int(cli.ptyInfo.WidthColumns), Height: int(cli.ptyInfo.HeightRows)})
			close(cli.msgQueue)

			cli.tui = tea.NewProgram(model,
				tea.WithInput(cmd.InOrStdin()),
				tea.WithOutput(cmd.OutOrStdout()),
				tea.WithAltScreen(),
				tea.WithContext(cmd.Context()),
				tea.WithEnvironment([]string{"TERM=" + cli.ptyInfo.TermEnv}),
				tea.WithMouseCellMotion(),
			)

			if len(cli.msgQueue) > 0 {
				go func() {
					for msg := range cli.msgQueue {
						cli.tui.Send(msg)
					}
				}()
			}
			_, err := cli.tui.Run()
			if err != nil {
				return err
			}
			return nil
		},
	})
}

// ErrHandoff is a sentinel error to indicate that the command triggered a handoff,
// and we should not automatically disconnect
var ErrHandoff = errors.New("handoff")

// ErrDeleteSessionOnExit is a sentinel error to indicate that the authorized
// session should be deleted once the SSH connection ends.
var ErrDeleteSessionOnExit = errors.New("delete_session_on_exit")

func (cli *CLI) AddPortalCommand(ctrl ChannelControlInterface) {
	cli.AddCommand(&cobra.Command{
		Use:   "portal",
		Short: "Interactive route portal",
		Annotations: map[string]string{
			"interactive": "",
		},
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			var routes []string
			for r := range ctrl.AllSSHRoutes() {
				routes = append(routes, fmt.Sprintf("%s@%s", *ctrl.Username(), strings.TrimPrefix(r.From, "ssh://")))
			}
			items := []list.Item{}
			for _, route := range routes {
				items = append(items, item(route))
			}
			l := list.New(items, itemDelegate{}, int(cli.ptyInfo.WidthColumns-2), int(cli.ptyInfo.HeightRows-2))
			l.Title = "Connect to which server?"
			l.SetShowStatusBar(false)
			l.SetFilteringEnabled(false)
			l.Styles.Title = titleStyle
			l.Styles.PaginationStyle = paginationStyle
			l.Styles.HelpStyle = helpStyle

			cli.SendTeaMsg(tea.WindowSizeMsg{Width: int(cli.ptyInfo.WidthColumns), Height: int(cli.ptyInfo.HeightRows)})
			close(cli.msgQueue)

			cli.tui = tea.NewProgram(model{list: l},
				tea.WithInput(cmd.InOrStdin()),
				tea.WithOutput(cmd.OutOrStdout()),
				tea.WithAltScreen(),
				tea.WithContext(cmd.Context()),
				tea.WithEnvironment([]string{"TERM=" + cli.ptyInfo.TermEnv}),
			)

			if len(cli.msgQueue) > 0 {
				go func() {
					for msg := range cli.msgQueue {
						cli.tui.Send(msg)
					}
				}()
			}
			answer, err := cli.tui.Run()
			if err != nil {
				return err
			}
			if answer.(model).choice == "" {
				return nil // quit/ctrl+c
			}

			username, hostname, _ := strings.Cut(answer.(model).choice, "@")
			// Perform authorize check for this route
			if username != cli.username {
				panic("bug: username mismatch")
			}
			if hostname == "" {
				panic("bug: hostname is empty")
			}

			handoffMsg, err := ctrl.PrepareHandoff(cmd.Context(), hostname, cli.ptyInfo)
			if err != nil {
				return err
			}
			if err := ctrl.SendControlAction(handoffMsg); err != nil {
				return err
			}
			return ErrHandoff
		},
	})
}

func (cli *CLI) SendTeaMsg(msg tea.Msg) {
	if cli.tui != nil {
		cli.tui.Send(msg)
	} else {
		cli.msgQueue <- msg
	}
}

var (
	titleStyle        = lipgloss.NewStyle().MarginLeft(2)
	itemStyle         = lipgloss.NewStyle().PaddingLeft(4)
	selectedItemStyle = lipgloss.NewStyle().PaddingLeft(2).Foreground(lipgloss.Color("170"))
	paginationStyle   = list.DefaultStyles().PaginationStyle.PaddingLeft(4)
	helpStyle         = list.DefaultStyles().HelpStyle.PaddingLeft(4).PaddingBottom(1)
)

type item string

func (i item) FilterValue() string { return "" }

type itemDelegate struct{}

func (d itemDelegate) Height() int                             { return 1 }
func (d itemDelegate) Spacing() int                            { return 0 }
func (d itemDelegate) Update(_ tea.Msg, _ *list.Model) tea.Cmd { return nil }
func (d itemDelegate) Render(w io.Writer, m list.Model, index int, listItem list.Item) {
	i, ok := listItem.(item)
	if !ok {
		return
	}

	str := fmt.Sprintf("%d. %s", index+1, i)

	fn := itemStyle.Render
	if index == m.Index() {
		fn = func(s ...string) string {
			return selectedItemStyle.Render("> " + strings.Join(s, " "))
		}
	}

	fmt.Fprint(w, fn(str))
}

type model struct {
	list     list.Model
	choice   string
	quitting bool
}

func (m model) Init() tea.Cmd {
	return nil
}

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.list.SetWidth(msg.Width - 2)
		m.list.SetHeight(msg.Height - 2)
		return m, nil

	case tea.KeyMsg:
		switch keypress := msg.String(); keypress {
		case "q", "ctrl+c":
			m.quitting = true
			return m, tea.Quit

		case "enter":
			i, ok := m.list.SelectedItem().(item)
			if ok {
				m.choice = string(i)
			}
			return m, tea.Quit
		}
	}

	var cmd tea.Cmd
	m.list, cmd = m.list.Update(msg)
	return m, cmd
}

func (m model) View() string {
	return "\n" + m.list.View()
}
