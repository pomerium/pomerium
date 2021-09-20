// Package main implements the pomerium-cli.
package main

import (
	"crypto/tls"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/pomerium/pomerium/pkg/cryptutil"
)

var rootCmd = &cobra.Command{
	Use: "pomerium-cli",
}

func main() {
	err := rootCmd.Execute()
	if err != nil {
		fatalf("%s", err.Error())
	}
}

func fatalf(msg string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, msg+"\n", args...)
	os.Exit(1)
}

var tlsOptions struct {
	disableTLSVerification bool
	alternateCAPath        string
	caCert                 string
}

func addTLSFlags(cmd *cobra.Command) {
	flags := cmd.Flags()
	flags.BoolVar(&tlsOptions.disableTLSVerification, "disable-tls-verification", false,
		"disables TLS verification")
	flags.StringVar(&tlsOptions.alternateCAPath, "alternate-ca-path", "",
		"path to CA certificate to use for HTTP requests")
	flags.StringVar(&tlsOptions.caCert, "ca-cert", "",
		"base64-encoded CA TLS certificate to use for HTTP requests")
}

func getTLSConfig() *tls.Config {
	cfg := new(tls.Config)
	if tlsOptions.disableTLSVerification {
		cfg.InsecureSkipVerify = true
	}
	if tlsOptions.caCert != "" {
		var err error
		cfg.RootCAs, err = cryptutil.GetCertPool(tlsOptions.caCert, tlsOptions.alternateCAPath)
		if err != nil {
			fatalf("%s", err)
		}
	}
	return cfg
}

var browserOptions struct {
	command string
}

func addBrowserFlags(cmd *cobra.Command) {
	flags := cmd.Flags()
	flags.StringVar(&browserOptions.command, "browser-cmd", "",
		"custom browser command to run when opening a URL")
}
