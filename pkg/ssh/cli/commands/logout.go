package commands

import (
	"github.com/pomerium/pomerium/pkg/ssh/cli"
	"github.com/spf13/cobra"
)

func NewLogoutCommand(intcli cli.InternalCLI) *cobra.Command {
	return &cobra.Command{
		Use:   "logout",
		Short: "Log out",
		RunE: func(_ *cobra.Command, _ []string) error {
			return cli.ErrDeleteSessionOnExit
		},
	}
}
