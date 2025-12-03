package ssh

import (
	"errors"
	"fmt"
	"io"
	"strings"

	tea "charm.land/bubbletea/v2"
	"github.com/muesli/termenv"
	"github.com/spf13/cobra"

	"github.com/pomerium/envoy-custom/api/extensions/filters/network/ssh"
	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/pkg/ssh/tui"
)

type CLI struct {
	*cobra.Command
	tui      *tea.Program
	tuiDone  chan struct{}
	msgQueue chan tea.Msg
	ptyInfo  *ssh.SSHDownstreamPTYInfo
	username string
	stdin    io.Reader
	stdout   io.Writer
	stderr   io.Writer
}

func NewCLI(
	cfg *config.Config,
	ctrl ChannelControlInterface,
	ptyInfo *ssh.SSHDownstreamPTYInfo,
	stdin io.Reader,
	stdout io.Writer,
	stderr io.Writer,
) *CLI {
	cmd := &cobra.Command{
		Use: "pomerium",
		PersistentPreRunE: func(cmd *cobra.Command, _ []string) error {
			_, cmdIsInteractive := cmd.Annotations["interactive"]
			switch {
			case (ptyInfo == nil) && cmdIsInteractive:
				return fmt.Errorf("\x1b[31m'%s' is an interactive command and requires a TTY (try passing '-t' to ssh)\x1b[0m", cmd.Use)
			}
			return nil
		},
	}

	cmd.CompletionOptions.DisableDefaultCmd = true
	// set a non-nil args list, otherwise it will read from os.Args by default
	cmd.SetArgs([]string{})
	cmd.SetIn(stdin)
	cmd.SetOut(stderr)
	cmd.SetErr(stderr)
	cmd.SilenceUsage = true

	cli := &CLI{
		Command:  cmd,
		tui:      nil,
		tuiDone:  make(chan struct{}),
		msgQueue: make(chan tea.Msg, 256),
		ptyInfo:  ptyInfo,
		username: *ctrl.Username(),
		stdin:    stdin,
		stdout:   stdout,
		stderr:   stderr,
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
		RunE: func(_ *cobra.Command, _ []string) error {
			_, _ = cli.stderr.Write([]byte("Logged out successfully\n"))
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
				return fmt.Errorf("couldn't fetch session: %w", err)
			}
			_, _ = cli.stderr.Write(s)
			return nil
		},
	})
}

type sshEnviron struct {
	Env map[string]string
}

// Environ implements termenv.Environ.
func (s *sshEnviron) Environ() []string {
	kv := make([]string, 0, len(s.Env))
	for k, v := range s.Env {
		kv = append(kv, fmt.Sprintf("%s=%s", k, v))
	}
	return kv
}

// Getenv implements termenv.Environ.
func (s *sshEnviron) Getenv(key string) string {
	return s.Env[key]
}

var _ termenv.Environ = (*sshEnviron)(nil)

const (
	ptyWidthMax  = 512
	ptyHeightMax = 512
)

func (cli *CLI) AddTunnelCommand(ctrl ChannelControlInterface) {
	cli.AddCommand(&cobra.Command{
		Use:    "tunnel",
		Short:  "tunnel status",
		Hidden: true,
		Annotations: map[string]string{
			"interactive": "",
		},
		RunE: func(cmd *cobra.Command, _ []string) error {
			env := &sshEnviron{
				Env: map[string]string{
					"TERM":      cli.ptyInfo.TermEnv,
					"TTY_FORCE": "1",

					// Important: disables synchronized output querying which I think
					// might be causing the renderer to get stuck
					"SSH_TTY": "1",
				},
			}

			prog := tui.NewTunnelStatusProgram(cmd.Context(),
				tea.WithInput(cli.stdin),
				tea.WithWindowSize(int(min(cli.ptyInfo.WidthColumns, ptyWidthMax)), int(min(cli.ptyInfo.HeightRows, ptyHeightMax))),
				tea.WithOutput(termenv.NewOutput(cli.stdout, termenv.WithEnvironment(env), termenv.WithUnsafe())),
				tea.WithEnvironment(env.Environ()),
			)
			cli.tui = prog.Program
			defer close(cli.tuiDone)

			initDone := make(chan struct{})
			mgr := ctrl.PortForwardManager()

			go func() {
				mgr.AddUpdateListener(prog)
				defer mgr.RemoveUpdateListener(prog)
				close(initDone)
				for {
					select {
					case <-cli.tuiDone:
						return
					case msg := <-cli.msgQueue:
						cli.tui.Send(msg)
					}
				}
			}()
			_, err := prog.Run()
			<-initDone
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
		RunE: func(cmd *cobra.Command, _ []string) error {
			var routes []string
			for r := range ctrl.AllSSHRoutes() {
				routes = append(routes, fmt.Sprintf("%s@%s", *ctrl.Username(), strings.TrimPrefix(r.From, "ssh://")))
			}
			env := &sshEnviron{
				Env: map[string]string{
					"TERM":      cli.ptyInfo.TermEnv,
					"TTY_FORCE": "1",
					"SSH_TTY":   "1",
				},
			}
			signedWidth := int(min(cli.ptyInfo.WidthColumns, ptyWidthMax))
			signedHeight := int(min(cli.ptyInfo.HeightRows, ptyHeightMax))
			prog := tui.NewPortalProgram(cmd.Context(), routes, max(0, signedWidth-2), max(0, signedHeight-2),
				tea.WithInput(cli.stdin),
				tea.WithWindowSize(signedWidth, signedHeight),
				tea.WithOutput(termenv.NewOutput(cli.stdout, termenv.WithEnvironment(env), termenv.WithUnsafe())),
				tea.WithEnvironment(env.Environ()),
			)
			cli.tui = prog.Program

			choice, err := prog.Run()
			if err != nil {
				return err
			}
			if choice == "" {
				return nil // quit/ctrl+c
			}

			username, hostname, _ := strings.Cut(choice, "@")
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
	select {
	case <-cli.tuiDone:
	case cli.msgQueue <- msg:
	}
}
