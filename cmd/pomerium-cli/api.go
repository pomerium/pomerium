package main

import (
	"fmt"
	"net"
	"net/http"
	"os"
	"path"

	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"github.com/hashicorp/go-multierror"
	"github.com/spf13/cobra"

	"github.com/pomerium/pomerium/internal/cli"
	pb "github.com/pomerium/pomerium/pkg/grpc/cli"
)

func init() {
	rootCmd.AddCommand(apiCommand())
}

type apiCmd struct {
	listenAddr string
	configPath string

	cobra.Command
}

func apiCommand() *cobra.Command {
	cmd := &apiCmd{
		Command: cobra.Command{
			Use:    "api",
			Short:  "run api server",
			Hidden: true,
		},
	}
	cmd.RunE = cmd.exec

	cfgDir, err := os.UserConfigDir()
	if err == nil {
		cfgDir = path.Join(cfgDir, "PomeriumDesktop", "config.json")
	}
	flags := cmd.Flags()
	flags.StringVar(&cmd.listenAddr, "listen-addr", "127.0.0.1:5627", "address api server should listen to")
	flags.StringVar(&cmd.configPath, "config-path", cfgDir, "path to config file")

	return &cmd.Command
}

func (cmd *apiCmd) makeConfigPath() error {
	if cmd.configPath == "" {
		return fmt.Errorf("config file path could not be determined")
	}

	return os.MkdirAll(path.Dir(cmd.configPath), 0700)
}

func (cmd *apiCmd) exec(c *cobra.Command, args []string) error {
	if err := cmd.makeConfigPath(); err != nil {
		return fmt.Errorf("config %s: %w", cmd.configPath, err)
	}

	lis, err := net.Listen("tcp", cmd.listenAddr)
	if err != nil {
		return err
	}

	srv, err := cli.NewServer(cli.FileConfigProvider(cmd.configPath))
	if err != nil {
		return err
	}

	ctx := c.Context()

	mux := runtime.NewServeMux()
	if err := multierror.Append(
		pb.RegisterConfigHandlerServer(ctx, mux, srv),
		pb.RegisterListenerHandlerServer(ctx, mux, srv),
		mux.HandlePath(http.MethodGet, "/updates", cli.ListenerUpdateStream(srv)),
	).ErrorOrNil(); err != nil {
		return err
	}

	return http.Serve(lis, mux)
}
