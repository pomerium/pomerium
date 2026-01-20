package commands

import (
	"fmt"

	"github.com/pomerium/pomerium/pkg/ssh/api"
	"github.com/pomerium/pomerium/pkg/ssh/cli"
	"github.com/spf13/cobra"
)

func NewWhoamiCommand(ctrl api.ChannelControlInterface, cli cli.InternalCLI) *cobra.Command {
	return &cobra.Command{
		Use:   "whoami",
		Short: "Show details for the current session",
		RunE: func(cmd *cobra.Command, _ []string) error {
			s, err := ctrl.GetSession(cmd.Context())
			if err != nil {
				return fmt.Errorf("couldn't fetch session: %w", err)
			}
			_, _ = cli.Stderr().Write(s.Format())
			return nil
		},
	}
}
