package cmd

import "os"

const (
	// PomeriumZeroTokenEnv is the environment variable name for the API token.
	//nolint: gosec
	PomeriumZeroTokenEnv = "POMERIUM_ZERO_TOKEN"
)

func getToken() string {
	return os.Getenv(PomeriumZeroTokenEnv)
}
