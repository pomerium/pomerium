package cmd

import (
	"context"
	"errors"

	"github.com/spf13/cobra"

	zero "github.com/pomerium/pomerium/internal/zero/api"
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
		PersistentPreRunE: func(cmd *cobra.Command, _ []string) error {
			configFlag := cmd.InheritedFlags().Lookup("config")
			var configFile string
			if configFlag != nil {
				configFile = configFlag.Value.String()
			}

			if err := setupLogger(); err != nil {
				return err
			}
			var token string
			if tokenFlag := cmd.InheritedFlags().Lookup("token"); tokenFlag != nil && tokenFlag.Changed {
				token = tokenFlag.Value.String()
			} else {
				token = getToken(configFile)
			}
			if token == "" {
				return errors.New("no token provided")
			}

			var clusterAPIEndpoint string
			if endpointFlag := cmd.InheritedFlags().Lookup("cluster-api-endpoint"); endpointFlag != nil && endpointFlag.Changed {
				clusterAPIEndpoint = endpointFlag.Value.String()
			} else {
				clusterAPIEndpoint = getClusterAPIEndpoint()
			}

			client, err := zero.NewAPI(cmd.Context(),
				zero.WithAPIToken(token),
				zero.WithClusterAPIEndpoint(clusterAPIEndpoint),
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
	cmd.PersistentFlags().String("config", "", "Specify configuration file location")
	cmd.PersistentFlags().String("token", "", "Pomerium Zero Token (default: $POMERIUM_ZERO_TOKEN)")
	cmd.PersistentFlags().String("cluster-api-endpoint", "", "Pomerium Zero Cluster API Endpoint (default: $CLUSTER_API_ENDPOINT)")
	cmd.PersistentFlags().Lookup("cluster-api-endpoint").Hidden = true

	return cmd
}
