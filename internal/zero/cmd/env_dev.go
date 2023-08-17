//go:build !release

package cmd

import "os"

func getConnectAPIEndpoint() string {
	connectServerEndpoint := os.Getenv("CONNECT_SERVER_ENDPOINT")
	if connectServerEndpoint == "" {
		connectServerEndpoint = "http://localhost:8721"
	}
	return connectServerEndpoint
}

func getClusterAPIEndpoint() string {
	clusterAPIEndpoint := os.Getenv("CLUSTER_API_ENDPOINT")
	if clusterAPIEndpoint == "" {
		clusterAPIEndpoint = "http://localhost:8720/cluster/v1"
	}
	return clusterAPIEndpoint
}
