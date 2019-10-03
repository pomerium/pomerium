package config // import "github.com/pomerium/pomerium/internal/config"

const (
	// ServiceAll represents running all services in "all-in-one" mode
	ServiceAll = "all"
	// ServiceProxy represents running the proxy service component
	ServiceProxy = "proxy"
	// ServiceAuthorize represents running the authorize service component
	ServiceAuthorize = "authorize"
	// ServiceAuthenticate represents running the authenticate service component
	ServiceAuthenticate = "authenticate"
)

// IsValidService checks to see if a service is a valid service mode
func IsValidService(s string) bool {
	switch s {
	case
		ServiceAll,
		ServiceProxy,
		ServiceAuthorize,
		ServiceAuthenticate:
		return true
	}
	return false
}

// IsAuthenticate checks to see if we should be running the authenticate service
func IsAuthenticate(s string) bool {
	switch s {
	case
		ServiceAll,
		ServiceAuthenticate:
		return true
	}
	return false
}

// IsAuthorize checks to see if we should be running the authorize service
func IsAuthorize(s string) bool {
	switch s {
	case
		ServiceAll,
		ServiceAuthorize:
		return true
	}
	return false
}

// IsProxy checks to see if we should be running the proxy service
func IsProxy(s string) bool {
	switch s {
	case
		ServiceAll,
		ServiceProxy:
		return true
	}
	return false
}

// IsAll checks to see if we should be running all services
func IsAll(s string) bool {
	return s == ServiceAll
}
