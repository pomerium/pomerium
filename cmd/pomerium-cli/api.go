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
	"golang.org/x/sync/errgroup"
	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"

	"github.com/pomerium/pomerium/internal/cli"
	"github.com/pomerium/pomerium/internal/log"
	pb "github.com/pomerium/pomerium/pkg/grpc/cli"
)

func init() {
	rootCmd.AddCommand(apiCommand())
}

type apiCmd struct {
	jsonRPCAddr string
	grpcAddr    string
	configPath  string

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
	flags.StringVar(&cmd.jsonRPCAddr, "json-addr", "127.0.0.1:8900", "address json api server should listen to")
	flags.StringVar(&cmd.grpcAddr, "grpc-addr", "127.0.0.1:8800", "address json api server should listen to")
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

	srv, err := cli.NewServer(c.Context(), cli.FileConfigProvider(cmd.configPath))
	if err != nil {
		return err
	}

	ctx := c.Context()
	eg, ctx := errgroup.WithContext(ctx)

	eg.Go(func() error {
		lis, err := net.Listen("tcp", cmd.jsonRPCAddr)
		if err != nil {
			return err
		}
		log.Info(ctx).Str("address", lis.Addr().String()).Msg("json-rpc")

		mux := runtime.NewServeMux()
		if err := multierror.Append(
			pb.RegisterConfigHandlerServer(ctx, mux, srv),
			pb.RegisterListenerHandlerServer(ctx, mux, srv),
			mux.HandlePath(http.MethodGet, "/listener/events", cli.ListenerUpdateStream(srv)),
		).ErrorOrNil(); err != nil {
			return err
		}
		return http.Serve(lis, mux)
	})
	eg.Go(func() error {
		lis, err := net.Listen("tcp", cmd.grpcAddr)
		if err != nil {
			return err
		}
		log.Info(ctx).Str("address", lis.Addr().String()).Msg("grpc")

		var opts []grpc.ServerOption
		grpcSrv := grpc.NewServer(opts...)
		pb.RegisterConfigServer(grpcSrv, srv)
		pb.RegisterListenerServer(grpcSrv, srv)
		reflection.Register(grpcSrv)
		return grpcSrv.Serve(lis)
	})

	return eg.Wait()
}
