package cmd

import (
	"bytes"
	"fmt"
	"os"
	"strings"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/pkg/envoy/files"
	"github.com/rs/zerolog"
	"github.com/spf13/cobra"
)

func BuildImportCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "import",
		Short: "Import an existing configuration to a Zero cluster",
		RunE: func(cmd *cobra.Command, _ []string) error {
			configFlag := cmd.InheritedFlags().Lookup("config")
			var configFile string
			if configFlag != nil {
				configFile = configFlag.Value.String()
			}
			if configFile == "" {
				// try looking up what pid 1 is using, we are likely in a container anyway
				info, err := os.ReadFile("/proc/1/cmdline")
				if err == nil {
					args := bytes.Split(info, []byte{0})
					if len(args) > 0 && strings.Contains(string(args[0]), "pomerium") {
						for i, arg := range args {
							if strings.Contains(string(arg), "-config") {
								if strings.Contains(string(arg), "-config=") {
									configFile = strings.Split(string(arg), "=")[1]
									cmd.PrintErrf("detected config file: %s\n", configFile)
								} else if len(args) > i+1 {
									configFile = string(args[i+1])
									cmd.PrintErrf("detected config file: %s\n", configFile)
								}
							}
						}
					}
				}

				// try some common locations
				if configFile == "" {
					if _, err := os.Stat("/pomerium/config.yaml"); err == nil {
						configFile = "/pomerium/config.yaml"
					} else if _, err := os.Stat("/etc/pomerium/config.yaml"); err == nil {
						configFile = "/etc/pomerium/config.yaml"
					} else if _, err := os.Stat("config.yaml"); err == nil {
						configFile = "config.yaml"
					}

					if configFile != "" {
						cmd.PrintErrf("detected config file: %s\n", configFile)
					}
				}
			}
			if configFile == "" {
				return fmt.Errorf("no config file provided")
			}
			log.SetLevel(zerolog.ErrorLevel)
			src, err := config.NewFileOrEnvironmentSource(configFile, files.FullVersion())
			if err != nil {
				return err
			}
			cfg := src.GetConfig()

			client := zeroClientFromContext(cmd.Context())
			quotas, err := client.GetQuotas(cmd.Context())
			if err != nil {
				return fmt.Errorf("error getting quotas: %w", err)
			}
			converted := cfg.Options.ToProto()
			ui := NewImportUI(converted, quotas)
			if err := ui.Run(cmd.Context()); err != nil {
				return err
			}
			ui.ApplySelections(converted)
			_, err = client.ImportConfig(cmd.Context(), converted)
			if err != nil {
				return fmt.Errorf("error importing config: %w", err)
			}
			cmd.PrintErrln("config imported successfully")
			return nil
		},
	}
	return cmd
}
