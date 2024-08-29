package cmd

import (
	"context"
	"fmt"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/pkg/envoy/files"
	"github.com/spf13/cobra"
)

func BuildImportCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "import",
		Short: "Import an existing configuration to a Zero cluster",
		RunE: func(cmd *cobra.Command, args []string) error {
			configFile := cmd.InheritedFlags().Lookup("config").Value.String()
			src, err := config.NewFileOrEnvironmentSource(configFile, files.FullVersion())
			if err != nil {
				return err
			}
			cfgC := make(chan *config.Config, 1)
			src.OnConfigChange(cmd.Context(), func(ctx context.Context, cfg *config.Config) {
				cmd.Println("config loaded")
				cfgC <- cfg
			})
			if cfg := src.GetConfig(); cfg != nil {
				cfgC <- cfg
			}

			var cfg *config.Config
			select {
			case <-cmd.Context().Done():
				return cmd.Context().Err()
			case cfg = <-cfgC:
			}

			client := zeroClientFromContext(cmd.Context())
			_, err = client.ImportConfig(cmd.Context(), cfg.Options.ToProto())
			if err != nil {
				return fmt.Errorf("error importing config: %w", err)
			}
			cmd.Println("config imported successfully")
			return nil
		},
	}
	cmd.MarkFlagRequired("config")
	return cmd
}
