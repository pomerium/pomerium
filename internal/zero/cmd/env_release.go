//go:build release

package cmd

func getConnectAPIEndpoint() string {
	return "https://connect.pomerium.app"
}

func getClusterAPIEndpoint() string {
	return "https://console.pomerium.app/cluster/v1"
}
