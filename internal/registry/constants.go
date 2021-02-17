package registry

import (
	"errors"
	"time"
)

const (
	// callAfterTTLFactor will request to report back again after TTL/callAfterTTLFactor time
	callAfterTTLFactor = 2
	// purgeAfterTTLFactor will purge keys with TTL * purgeAfterTTLFactor time
	purgeAfterTTLFactor = 1
	// min reporting ttl
	minTTL = time.Second
	// path metrics are available at
	defaultMetricsPath = "/metrics"
)

var (
	errNoMetricsAddr = errors.New("no metrics address provided")
	errNoMetricsPort = errors.New("no metrics port provided")
)
