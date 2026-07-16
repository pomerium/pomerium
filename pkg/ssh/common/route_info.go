package common

import "github.com/pomerium/pomerium/config"

type RouteInfo struct {
	From      string
	To        config.WeightedURLs
	Hostname  string // not including port
	Port      uint32
	ClusterID string
}
