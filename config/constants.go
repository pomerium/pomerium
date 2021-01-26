package config

import (
	"errors"

	"google.golang.org/protobuf/encoding/protojson"
)

const (
	policyKey    = "policy"
	toKey        = "to"
	weightsKey   = "_to_weights"
	envoyOptsKey = "_envoy_opts"
)

var (
	errKeysMustBeStrings   = errors.New("cannot convert nested map: all keys must be strings")
	errZeroWeight          = errors.New("zero load balancing weight not permitted")
	errEndpointWeightsSpec = errors.New("either no weights should be provided, or all endpoints must have non-zero weight specified")
)

var (
	protoPartial = protojson.UnmarshalOptions{AllowPartial: true, DiscardUnknown: true}
)
