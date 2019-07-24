package config // import "github.com/pomerium/pomerium/internal/config"

// IsValidService checks to see if a service is a valid service mode
func IsValidService(s string) bool {
	switch s {
	case
		"all",
		"proxy",
		"authorize",
		"authenticate":
		return true
	}
	return false
}

// IsAuthenticate checks to see if we should be running the authenticate service
func IsAuthenticate(s string) bool {
	switch s {
	case
		"all",
		"authenticate":
		return true
	}
	return false
}

// IsAuthorize checks to see if we should be running the authorize service
func IsAuthorize(s string) bool {
	switch s {
	case
		"all",
		"authorize":
		return true
	}
	return false
}

// IsProxy checks to see if we should be running the proxy service
func IsProxy(s string) bool {
	switch s {
	case
		"all",
		"proxy":
		return true
	}
	return false
}
