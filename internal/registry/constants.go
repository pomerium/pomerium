package registry

const (
	// callAfterTTLFactor will request to report back again after TTL/callAfterTTLFactor time
	callAfterTTLFactor = 2
	// purgeAfterTTLFactor will purge keys with TTL * purgeAfterTTLFactor time
	purgeAfterTTLFactor = 5
)
