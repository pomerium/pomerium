package cmd

import (
	"os"

	"github.com/spf13/viper"
)

const (
	// PomeriumZeroTokenEnv is the environment variable name for the API token.
	//nolint: gosec
	PomeriumZeroTokenEnv = "POMERIUM_ZERO_TOKEN"
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
