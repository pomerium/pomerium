package cmd

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/viper"

	"github.com/pomerium/pomerium/internal/fileutil"
)

const (
	// PomeriumZeroTokenEnv is the environment variable name for the API token.
	//nolint: gosec
	PomeriumZeroTokenEnv = "POMERIUM_ZERO_TOKEN"

	// BootstrapConfigFileName can be set to override the default location of the bootstrap config file.
	BootstrapConfigFileName = "BOOTSTRAP_CONFIG_FILE"
	// BootstrapConfigWritebackURI controls how changes to the bootstrap config are persisted.
	// See controller.WithBootstrapConfigWritebackURI for details.
	BootstrapConfigWritebackURI = "BOOTSTRAP_CONFIG_WRITEBACK_URI"
)

func getToken(configFile string) string {
	if token, ok := os.LookupEnv(PomeriumZeroTokenEnv); ok {
		return token
	}

	if configFile != "" {
		// load the token from the config file
		v := viper.New()
		v.SetConfigFile(configFile)
		if v.ReadInConfig() == nil {
			return v.GetString("pomerium_zero_token")
		}
	}

	// we will fallback to normal pomerium if empty
	return ""
}

func getConnectAPIEndpoint() string {
	if endpoint := os.Getenv("CONNECT_SERVER_ENDPOINT"); endpoint != "" {
		return endpoint
	}
	return "https://connect.pomerium.app"
}

func getClusterAPIEndpoint() string {
	if endpoint := os.Getenv("CLUSTER_API_ENDPOINT"); endpoint != "" {
		return endpoint
	}
	return "https://console.pomerium.app/cluster/v1"
}

func getOTELAPIEndpoint() string {
	if endpoint := os.Getenv("POMERIUM_OTEL_ENDPOINT"); endpoint != "" {
		return endpoint
	}
	return "https://telemetry.pomerium.app"
}

func getBootstrapConfigFileName() (string, error) {
	if filename := os.Getenv(BootstrapConfigFileName); filename != "" {
		return filename, nil
	}
	dir := fileutil.CacheDir()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", fmt.Errorf("error creating cache directory: %w", err)
	}

	return filepath.Join(dir, "bootstrap.dat"), nil
}

func getBootstrapConfigWritebackURI() string {
	return os.Getenv(BootstrapConfigWritebackURI)
}
