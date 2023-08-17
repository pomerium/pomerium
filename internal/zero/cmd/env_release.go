//go:build release

package cmd

func getConnectAPIEndpoint() string {
	return "https://connect.pomerium.com"
}

func getClusterAPIEndpoint() string {
	return "https://console.pomerium.com/cluster/v1"
}
