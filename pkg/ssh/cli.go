package ssh

import (
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/list"
	"github.com/charmbracelet/bubbles/table"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/spf13/cobra"

	"github.com/pomerium/envoy-custom/api/extensions/filters/network/ssh"
	extensions_ssh "github.com/pomerium/envoy-custom/api/extensions/filters/network/ssh"
	"github.com/pomerium/pomerium/config"
)

type CLI struct {
	*cobra.Command
	tui      *tea.Program
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

var baseStyle = lipgloss.NewStyle().
	BorderStyle(lipgloss.NormalBorder()).
	BorderForeground(lipgloss.Color("240"))

type tunnelModel struct {
	rows     []table.Row
	rowIndex map[uint32]int
	table    table.Model
}

func (m tunnelModel) Init() tea.Cmd { return nil }

func (m tunnelModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmd tea.Cmd
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.table.SetWidth(msg.Width - 2)
		m.table.SetHeight(msg.Height - 2)
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
			channelId := event.InternalChannelOpened.ChannelId
			if _, ok := m.rowIndex[channelId]; !ok {
				m.rows = append(m.rows, table.Row{"", "", "", "", "", "", "", ""})
				m.rowIndex[channelId] = len(m.rows) - 1
			}
			m.rows[m.rowIndex[channelId]] = table.Row{
				fmt.Sprintf("%d", channelId),
				"OPEN",
				event.InternalChannelOpened.PeerAddress,
				"--",
				"--",
				"--",
				"--",
				"--",
			}
			m.table.SetRows(m.rows)
		case *extensions_ssh.ChannelEvent_InternalChannelClosed:
			index, ok := m.rowIndex[event.InternalChannelClosed.ChannelId]
			if ok {
				m.rows[index][1] = "CLOSED"
				m.rows[index][3] = fmt.Sprint(event.InternalChannelClosed.Stats.RxBytesTotal)
				m.rows[index][4] = fmt.Sprint(event.InternalChannelClosed.Stats.RxPacketsTotal)
				m.rows[index][5] = fmt.Sprint(event.InternalChannelClosed.Stats.TxBytesTotal)
				m.rows[index][6] = fmt.Sprint(event.InternalChannelClosed.Stats.TxPacketsTotal)
				m.rows[index][7] = event.InternalChannelClosed.Stats.ChannelDuration.AsDuration().Round(time.Millisecond).String()
				m.table.SetRows(m.rows)
			}
		}
	}
	m.table, cmd = m.table.Update(msg)
	return m, cmd
}

func (m tunnelModel) View() string {
	return "\n" + baseStyle.Render(m.table.View())
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
			t := table.New(
				table.WithColumns([]table.Column{
					{Title: "Channel", Width: 7},
					{Title: "Status", Width: 6},
					{Title: "Remote IP", Width: 21},
					{Title: "Rx Bytes", Width: 8},
					{Title: "Rx Msgs", Width: 8},
					{Title: "Tx Bytes", Width: 8},
					{Title: "Tx Msgs", Width: 8},
					{Title: "Duration", Width: 8},
				}),
				table.WithWidth(int(cli.ptyInfo.WidthColumns-2)),
				table.WithHeight(int(cli.ptyInfo.HeightRows-2)),
				table.WithFocused(true),
			)
			s := table.DefaultStyles()
			s.Header = s.Header.
				BorderStyle(lipgloss.NormalBorder()).
				BorderForeground(lipgloss.Color("240")).
				BorderBottom(true).
				Bold(false)
			s.Selected = s.Selected.
				Foreground(lipgloss.Color("229")).
				Background(lipgloss.Color("57")).
				Bold(false)
			t.SetStyles(s)
			cli.tui = tea.NewProgram(tunnelModel{
				rows:     []table.Row{},
				rowIndex: map[uint32]int{},
				table:    t,
			},
				tea.WithInput(cmd.InOrStdin()),
				tea.WithOutput(cmd.OutOrStdout()),
				tea.WithAltScreen(),
				tea.WithContext(cmd.Context()),
				tea.WithEnvironment([]string{"TERM=" + cli.ptyInfo.TermEnv}),
			)

			go cli.SendTeaMsg(tea.WindowSizeMsg{Width: int(cli.ptyInfo.WidthColumns), Height: int(cli.ptyInfo.HeightRows)})
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

			cli.tui = tea.NewProgram(model{list: l},
				tea.WithInput(cmd.InOrStdin()),
				tea.WithOutput(cmd.OutOrStdout()),
				tea.WithAltScreen(),
				tea.WithContext(cmd.Context()),
				tea.WithEnvironment([]string{"TERM=" + cli.ptyInfo.TermEnv}),
			)

			go cli.SendTeaMsg(tea.WindowSizeMsg{Width: int(cli.ptyInfo.WidthColumns), Height: int(cli.ptyInfo.HeightRows)})
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
