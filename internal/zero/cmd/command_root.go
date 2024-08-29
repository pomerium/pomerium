package cmd

import (
	"context"
	"errors"

	zero "github.com/pomerium/pomerium/internal/zero/api"
	"github.com/spf13/cobra"
)

type zeroClientContextKeyType struct{}

var zeroClientContextKey zeroClientContextKeyType

func zeroClientFromContext(ctx context.Context) *zero.API {
	return ctx.Value(zeroClientContextKey).(*zero.API)
}

func BuildRootCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "zero",
		Short: "Interact with the Pomerium Zero cloud service",
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			configFile := cmd.InheritedFlags().Lookup("config").Value.String()

			if err := setupLogger(); err != nil {
				return err
			}
			token := getToken(configFile)
			if token == "" {
				return errors.New("no token provided")
			}

			client, err := zero.NewAPI(cmd.Context(),
				zero.WithAPIToken(token),
				zero.WithClusterAPIEndpoint(getClusterAPIEndpoint()),
				zero.WithConnectAPIEndpoint(getConnectAPIEndpoint()),
				zero.WithOTELEndpoint(getOTELAPIEndpoint()),
			)
			if err != nil {
				return err
			}
			cmd.SetContext(context.WithValue(cmd.Context(), zeroClientContextKey, client))
			return nil
		},
	}

	cmd.AddCommand(BuildImportCmd())
	return cmd
}
