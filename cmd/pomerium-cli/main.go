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

func getTLSConfig(insecureSkipVerify bool, caCert, alternateCAPath string) *tls.Config {
	cfg := new(tls.Config)
	if insecureSkipVerify {
		cfg.InsecureSkipVerify = true
	}
	if caCert != "" {
		var err error
		cfg.RootCAs, err = cryptutil.GetCertPool(caCert, alternateCAPath)
		if err != nil {
			fatalf("%s", err)
		}
	}
	return cfg
}
