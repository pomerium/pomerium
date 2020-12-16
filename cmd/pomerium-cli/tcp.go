package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/rs/zerolog"
	"github.com/spf13/cobra"

	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/internal/tcptunnel"
)

var tcpCmdOptions struct {
	listen      string
	pomeriumURL string
}

func init() {
	flags := tcpCmd.Flags()
	flags.StringVar(&tcpCmdOptions.listen, "listen", "127.0.0.1:0",
		"local address to start a listener on")
	flags.StringVar(&tcpCmdOptions.pomeriumURL, "pomerium-url", "",
		"the URL of the pomerium server to connect too")
	rootCmd.AddCommand(tcpCmd)
}

var tcpCmd = &cobra.Command{
	Use:  "tcp destination",
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		dstHost := args[0]
		dstHostname, _, err := net.SplitHostPort(dstHost)
		if err != nil {
			return fmt.Errorf("invalid destination: %w", err)
		}

		pomeriumURL := &url.URL{
			Scheme: "https",
			Host:   net.JoinHostPort(dstHostname, "443"),
		}
		if tcpCmdOptions.pomeriumURL != "" {
			pomeriumURL, err = url.Parse(tcpCmdOptions.pomeriumURL)
			if err != nil {
				return fmt.Errorf("invalid pomerium URL: %w", err)
			}
			if !strings.Contains(pomeriumURL.Host, ":") {
				if pomeriumURL.Scheme == "https" {
					pomeriumURL.Host = net.JoinHostPort(pomeriumURL.Hostname(), "443")
				} else {
					pomeriumURL.Host = net.JoinHostPort(pomeriumURL.Hostname(), "80")
				}
			}
		}

		var tlsConfig *tls.Config
		if pomeriumURL.Scheme == "https" {
			tlsConfig = new(tls.Config)
		}

		l := zerolog.New(zerolog.ConsoleWriter{Out: os.Stderr})
		log.SetLogger(&l)

		c := make(chan os.Signal, 1)
		signal.Notify(c, os.Interrupt, syscall.SIGTERM, syscall.SIGHUP)
		ctx, cancel := context.WithCancel(context.Background())
		go func() {
			<-c
			cancel()
		}()

		err = tcptunnel.New(
			tcptunnel.WithDestinationHost(dstHost),
			tcptunnel.WithProxyHost(pomeriumURL.Host),
			tcptunnel.WithTLSConfig(tlsConfig),
		).RunListener(ctx, tcpCmdOptions.listen)
		if err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "%s\n", err.Error())
			os.Exit(1)
		}

		return nil
	},
}
