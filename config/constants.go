package config

import "errors"

const (
	policyKey      = "policy"
	toKey          = "to"
	healthCheckKey = "health_check"
)

var (
	errKeysMustBeStrings = errors.New("cannot convert nested map: all keys must be strings")
)
