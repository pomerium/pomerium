package ssh

import (
	"fmt"
	"strings"

	tea "charm.land/bubbletea/v2"
	"github.com/muesli/termenv"
	"github.com/spf13/cobra"

	extensions_ssh "github.com/pomerium/envoy-custom/api/extensions/filters/network/ssh"
	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/pkg/ssh/tui"
)

type DefaultCLIController struct {
	Config *config.Config
}

// Configure implements InternalCLIController.
func (cc *DefaultCLIController) Configure(root *cobra.Command, ctrl ChannelControlInterface, cli InternalCLI) {
	if cc.Config.Options.IsRuntimeFlagSet(config.RuntimeFlagSSHRoutesPortal) {
		root.AddCommand(NewPortalCommand(ctrl, cli))
	}
	root.AddCommand(NewLogoutCommand(cli))
	root.AddCommand(NewWhoamiCommand(ctrl, cli))
	root.AddCommand(NewTunnelCommand(ctrl, cli))
}

// DefaultArgs implements InternalCLIController.
func (cc *DefaultCLIController) DefaultArgs(modeHint extensions_ssh.InternalCLIModeHint) []string {
	switch modeHint {
	default:
		fallthrough
	case extensions_ssh.InternalCLIModeHint_MODE_DEFAULT:
		if cc.Config.Options.IsRuntimeFlagSet(config.RuntimeFlagSSHRoutesPortal) {
			return []string{"portal"}
		}
		return []string{}
	case extensions_ssh.InternalCLIModeHint_MODE_TUNNEL_STATUS:
		return []string{"tunnel"}
	}
}

var _ InternalCLIController = (*DefaultCLIController)(nil)

func NewLogoutCommand(cli InternalCLI) *cobra.Command {
	return &cobra.Command{
		Use:           "logout",
		Short:         "Log out",
		SilenceErrors: true,
		RunE: func(_ *cobra.Command, _ []string) error {
			_, _ = cli.Stderr().Write([]byte("Logged out successfully\n"))
			return ErrDeleteSessionOnExit
		},
	}
}

func NewWhoamiCommand(ctrl ChannelControlInterface, cli InternalCLI) *cobra.Command {
	return &cobra.Command{
		Use:   "whoami",
		Short: "Show details for the current session",
		RunE: func(cmd *cobra.Command, _ []string) error {
			s, err := ctrl.FormatSession(cmd.Context())
			if err != nil {
				return fmt.Errorf("couldn't fetch session: %w", err)
			}
			_, _ = cli.Stderr().Write(s)
			return nil
		},
	}
}

const (
	ptyWidthMax  = 512
	ptyHeightMax = 512
)

func NewTunnelCommand(ctrl ChannelControlInterface, cli InternalCLI) *cobra.Command {
	return &cobra.Command{
		Use:    "tunnel",
		Short:  "tunnel status",
		Hidden: true,
		Annotations: map[string]string{
			"interactive": "",
		},
		RunE: func(cmd *cobra.Command, _ []string) error {
			ptyInfo := cli.PtyInfo()
			env := NewSSHEnviron(cli.PtyInfo())

			prog := tui.NewTunnelStatusProgram(cmd.Context(),
				tea.WithInput(cli.Stdin()),
				tea.WithWindowSize(int(min(cli.PtyInfo().WidthColumns, ptyWidthMax)), int(min(ptyInfo.HeightRows, ptyHeightMax))),
				tea.WithOutput(termenv.NewOutput(cli.Stdout(), termenv.WithEnvironment(env), termenv.WithUnsafe())),
				tea.WithEnvironment(env.Environ()),
			)

			mgr := ctrl.PortForwardManager()

			mgr.AddUpdateListener(prog)
			defer mgr.RemoveUpdateListener(prog)

			_, err := cli.RunProgram(prog.Program)
			return err
		},
	}
}

func NewPortalCommand(ctrl ChannelControlInterface, cli InternalCLI) *cobra.Command {
	return &cobra.Command{
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

			env := NewSSHEnviron(cli.PtyInfo())
			signedWidth := int(min(cli.PtyInfo().WidthColumns, ptyWidthMax))
			signedHeight := int(min(cli.PtyInfo().HeightRows, ptyHeightMax))
			prog := tui.NewPortalProgram(cmd.Context(), routes, max(0, signedWidth-2), max(0, signedHeight-2),
				tea.WithInput(cli.Stdin()),
				tea.WithWindowSize(signedWidth, signedHeight),
				tea.WithOutput(termenv.NewOutput(cli.Stdout(), termenv.WithEnvironment(env), termenv.WithUnsafe())),
				tea.WithEnvironment(env.Environ()),
			)

			m, err := cli.RunProgram(prog.Program)
			if err != nil {
				return err
			}
			choice := prog.Result(m)
			if choice == "" {
				return nil // quit/ctrl+c
			}

			username, hostname, _ := strings.Cut(choice, "@")
			// Perform authorize check for this route
			if username != *ctrl.Username() {
				panic("bug: username mismatch")
			}
			if hostname == "" {
				panic("bug: hostname is empty")
			}
			handoffMsg, err := ctrl.PrepareHandoff(cmd.Context(), hostname, cli.PtyInfo())
			if err != nil {
				return err
			}
			if err := ctrl.SendControlAction(handoffMsg); err != nil {
				return err
			}
			return ErrHandoff
		},
	}
}
