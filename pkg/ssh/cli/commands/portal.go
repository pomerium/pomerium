package commands

import (
	"fmt"
	"strings"

	tea "charm.land/bubbletea/v2"
	"github.com/muesli/termenv"
	"github.com/pomerium/pomerium/pkg/ssh/api"
	"github.com/pomerium/pomerium/pkg/ssh/cli"
	"github.com/pomerium/pomerium/pkg/ssh/tui"
	"github.com/spf13/cobra"
)

func NewPortalCommand(ctrl api.ChannelControlInterface, intcli cli.InternalCLI) *cobra.Command {
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

			env := cli.NewSSHEnviron(intcli.PtyInfo())
			signedWidth := int(min(intcli.PtyInfo().GetWidthColumns(), ptyWidthMax))
			signedHeight := int(min(intcli.PtyInfo().GetHeightRows(), ptyHeightMax))
			prog := tui.NewPortalProgram(cmd.Context(), routes, max(0, signedWidth-2), max(0, signedHeight-2),
				tea.WithInput(intcli.Stdin()),
				tea.WithWindowSize(signedWidth, signedHeight),
				tea.WithOutput(termenv.NewOutput(intcli.Stdout(), termenv.WithEnvironment(env), termenv.WithUnsafe())),
				tea.WithEnvironment(env.Environ()),
			)

			m, err := intcli.RunProgram(prog.Program)
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
			handoffMsg, err := ctrl.PrepareHandoff(cmd.Context(), hostname, intcli.PtyInfo())
			if err != nil {
				return err
			}
			if err := ctrl.SendControlAction(handoffMsg); err != nil {
				return err
			}
			return cli.ErrHandoff
		},
	}
}
