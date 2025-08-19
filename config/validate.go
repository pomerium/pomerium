package config

import (
	"fmt"
	"net"
	"strconv"
	"strings"
)

// ValidateCookieSameSite validates the cookie same site option.
func ValidateCookieSameSite(value string) error {
	value = strings.ToLower(value)
	switch value {
	case "", "strict", "lax", "none":
		return nil
	}
	return fmt.Errorf("unknown cookie_same_site: %s", value)
}

// ValidateMetricsAddress validates address for the metrics
func ValidateMetricsAddress(addr string) error {
	_, port, err := net.SplitHostPort(addr)
	if err != nil || port == "" {
		return fmt.Errorf("expected host:port")
	}

	p, err := strconv.Atoi(port)
	if err != nil {
		return fmt.Errorf("port must be a number")
	}
	if p <= 0 {
		return fmt.Errorf("expected positive port number")
	}

	return nil
}
