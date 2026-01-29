package commands

import (
	"github.com/spf13/cobra"

	"github.com/pomerium/pomerium/pkg/ssh/cli"
)

func NewLogoutCommand(_ cli.InternalCLI) *cobra.Command {
	return &cobra.Command{
		Use:   "logout",
		Short: "Log out",
		RunE: func(_ *cobra.Command, _ []string) error {
			return cli.ErrDeleteSessionOnExit
		},
	}
}
