package main

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"

	_ "github.com/pomerium/pomerium/pkg/grpc/audit"
	_ "github.com/pomerium/pomerium/pkg/grpc/config"
	_ "github.com/pomerium/pomerium/pkg/grpc/device"
	_ "github.com/pomerium/pomerium/pkg/grpc/identity"
	_ "github.com/pomerium/pomerium/pkg/grpc/registry"
	_ "github.com/pomerium/pomerium/pkg/grpc/session"
	_ "github.com/pomerium/pomerium/pkg/grpc/user"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/internal/version"
	"github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/grpcutil"
	"github.com/rs/zerolog"
	"github.com/spf13/cobra"
)

func BuildRootCmd() *cobra.Command {
	var configFile, address, sharedSecret string

	cmd := &cobra.Command{
		Use:          "dbctl",
		SilenceUsage: true,
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			log.SetLevel(zerolog.WarnLevel)
			src, err := config.NewFileOrEnvironmentSource(cmd.Context(), configFile, version.FullVersion())
			if err != nil {
				return err
			}
			cfg := src.GetConfig()

			var sharedKey []byte

			if sharedSecret != "" {
				var encoding *base64.Encoding
				if strings.Contains(sharedSecret, "_") || strings.Contains(sharedSecret, "-") {
					encoding = base64.URLEncoding
				} else {
					encoding = base64.StdEncoding
				}
				sharedKey, err = encoding.DecodeString(sharedSecret)
				if err != nil {
					return fmt.Errorf("decode shared_secret: %w", err)
				}
			} else {
				var encoding *base64.Encoding
				if strings.Contains(cfg.Options.SharedKey, "_") || strings.Contains(cfg.Options.SharedKey, "-") {
					encoding = base64.URLEncoding
				} else {
					encoding = base64.StdEncoding
				}
				var err error
				sharedKey, err = encoding.DecodeString(cfg.Options.SharedKey)
				if err != nil {
					return fmt.Errorf("decode shared_secret: %w", err)
				}
			}

			u := &url.URL{
				Scheme: "http",
				Host:   cfg.Options.GetGRPCAddr(),
			}
			if address != "" {
				u, err = url.Parse(address)
				if err != nil {
					return err
				}
			}
			cc, err := grpcutil.NewGRPCClientConn(cmd.Context(), &grpcutil.Options{
				Address:            u,
				ServiceName:        "databroker",
				SignedJWTKey:       sharedKey,
				InsecureSkipVerify: true,
			})
			if err != nil {
				return err
			}

			cmd.SetContext(databroker.DataBrokerServiceContextInjector.ContextWithClient(cmd.Context(),
				databroker.DataBrokerServiceContextInjector.NewClient(cc)))

			return nil
		},
	}

	cmd.AddCommand(databroker.BuildDataBrokerServiceCmd())

	cmd.PersistentFlags().StringVarP(&configFile, "config", "c", "", "config file")
	cmd.PersistentFlags().StringVarP(&address, "address", "a", "", "databroker grpc address (default: from config)")
	cmd.PersistentFlags().StringVarP(&sharedSecret, "shared-secret", "s", "", "databroker shared secret (default: from config)")

	return cmd
}

func Execute() {
	ctx, ca := context.WithCancel(context.Background())
	c := make(chan os.Signal, 2)
	signal.Notify(c, syscall.SIGINT, syscall.SIGTERM)
	rootCmd := BuildRootCmd()
	go func() {
		sig := <-c
		switch sig {
		case syscall.SIGINT:
			rootCmd.PrintErrln("\nShutting down... (press Ctrl+C again to force)")
		default:
			rootCmd.PrintErrf("Received %s, shutting down...", sig.String())
		}
		ca()
		<-c
		os.Exit(1)
	}()
	if err := rootCmd.ExecuteContext(ctx); err != nil {
		os.Exit(1)
	}
}

func main() {
	Execute()
}
