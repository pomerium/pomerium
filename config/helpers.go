package config

import (
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

// IsAll checks to see if we should be running all services
func IsAll(services string) bool {
	var isAuthenticate, isAuthorize, isDataBroker, isProxy bool
	for _, svc := range splitServices(services) {
		switch svc {
		case ServiceAll:
			isAuthenticate = true
			isAuthorize = true
			isDataBroker = true
			isProxy = true
		case ServiceAuthenticate:
			isAuthenticate = true
		case ServiceAuthorize:
			isAuthorize = true
		case ServiceCache, ServiceDataBroker:
			isDataBroker = true
		case ServiceProxy:
			isProxy = true
		}
	}
	return isAuthenticate && isAuthorize && isDataBroker && isProxy
}

// IsAuthenticate checks to see if we should be running the authenticate service
func IsAuthenticate(services string) bool {
	for _, svc := range splitServices(services) {
		switch svc {
		case ServiceAll, ServiceAuthenticate:
			return true
		}
	}
	return false
}

// IsAuthorize checks to see if we should be running the authorize service
func IsAuthorize(services string) bool {
	for _, svc := range splitServices(services) {
		switch svc {
		case ServiceAll, ServiceAuthorize:
			return true
		}
	}
	return false
}

// IsDataBroker checks to see if we should be running the databroker service
func IsDataBroker(services string) bool {
	for _, svc := range splitServices(services) {
		switch svc {
		case ServiceAll, ServiceCache, ServiceDataBroker:
			return true
		}
	}
	return false
}

// IsProxy checks to see if we should be running the proxy service
func IsProxy(services string) bool {
	for _, svc := range splitServices(services) {
		switch svc {
		case ServiceAll, ServiceProxy:
			return true
		}
	}
	return false
}

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
