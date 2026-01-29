package commands

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/pomerium/pomerium/pkg/ssh/api"
	"github.com/pomerium/pomerium/pkg/ssh/cli"
)

func NewWhoamiCommand(ic cli.InternalCLI, ctrl api.ChannelControlInterface) *cobra.Command {
	return &cobra.Command{
		Use:   "whoami",
		Short: "Show details for the current session",
		RunE: func(cmd *cobra.Command, _ []string) error {
			s, err := ctrl.GetSession(cmd.Context())
			if err != nil {
				return fmt.Errorf("couldn't fetch session: %w", err)
			}
			_, _ = ic.Stderr().Write(s.Format())
			return nil
		},
	}
}
