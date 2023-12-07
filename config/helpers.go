package config

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
func IsValidService(s string) bool {
	switch s {
	case
		ServiceAll,
		ServiceAuthenticate,
		ServiceAuthorize,
		ServiceCache,
		ServiceDataBroker,
		ServiceProxy:
		return true
	}
	return false
}

// IsAuthenticate checks to see if we should be running the authenticate service
func IsAuthenticate(s string) bool {
	switch s {
	case ServiceAll, ServiceAuthenticate:
		return true
	}
	return false
}

// IsAuthorize checks to see if we should be running the authorize service
func IsAuthorize(s string) bool {
	switch s {
	case ServiceAll, ServiceAuthorize:
		return true
	}
	return false
}

// IsProxy checks to see if we should be running the proxy service
func IsProxy(s string) bool {
	switch s {
	case ServiceAll, ServiceProxy:
		return true
	}
	return false
}

// IsDataBroker checks to see if we should be running the databroker service
func IsDataBroker(s string) bool {
	switch s {
	case
		ServiceAll,
		ServiceCache,
		ServiceDataBroker:
		return true
	}
	return false
}

// IsRegistry checks if this node should run the registry service
func IsRegistry(s string) bool {
	return IsDataBroker(s)
}

// IsAll checks to see if we should be running all services
func IsAll(s string) bool {
	return s == ServiceAll
}
