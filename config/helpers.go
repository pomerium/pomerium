package config

import (
	"slices"
	"strings"
)

const (
	// ServiceAll represents running all services in "all-in-one" mode
	ServiceAll = "all"
	// ServiceProxy represents running the proxy service component
	ServiceProxy = "proxy"
	// ServiceAuthorize represents running the authorize service component
	ServiceAuthorize = "authorize"
	// ServiceAuthenticate represents running the authenticate service component
	ServiceAuthenticate = "authenticate"
	// ServiceCache represents running the cache service component
	ServiceCache = "cache"
	// ServiceDataBroker represents running the databroker service component
	ServiceDataBroker = "databroker"
	// StoragePostgresName is the name of the Postgres storage backend
	StoragePostgresName = "postgres"
	// StorageInMemoryName is the name of the in-memory storage backend
	StorageInMemoryName = "memory"
)

// IsValidService checks to see if a service is a valid service mode
func IsValidService(services string) bool {
	svcs := splitServices(services)
	for _, svc := range svcs {
		switch svc {
		case
			ServiceAll,
			ServiceAuthenticate,
			ServiceAuthorize,
			ServiceCache,
			ServiceDataBroker,
			ServiceProxy:
			// valid
		default:
			return false
		}
	}
	return len(svcs) > 0
}

// IsAuthenticate checks to see if we should be running the authenticate service
func IsAuthenticate(services string) bool {
	return slices.Contains(splitServices(services), ServiceAll) ||
		slices.Contains(splitServices(services), ServiceAuthenticate)
}

// IsAuthorize checks to see if we should be running the authorize service
func IsAuthorize(services string) bool {
	return slices.Contains(splitServices(services), ServiceAll) ||
		slices.Contains(splitServices(services), ServiceAuthorize)
}

// IsProxy checks to see if we should be running the proxy service
func IsProxy(services string) bool {
	return slices.Contains(splitServices(services), ServiceAll) ||
		slices.Contains(splitServices(services), ServiceProxy)
}

// IsDataBroker checks to see if we should be running the databroker service
func IsDataBroker(services string) bool {
	return slices.Contains(splitServices(services), ServiceAll) ||
		slices.Contains(splitServices(services), ServiceCache) ||
		slices.Contains(splitServices(services), ServiceDataBroker)
}

// IsAll checks to see if we should be running all services
func IsAll(services string) bool {
	return slices.Contains(splitServices(services), ServiceAll)
}

func splitServices(raw string) []string {
	var svcs []string
	for _, s := range strings.Split(raw, ",") {
		s = strings.TrimSpace(strings.ToLower(s))
		if s != "" {
			svcs = append(svcs, s)
		}
	}
	return svcs
}
