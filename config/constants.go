package config

import (
	"errors"

	"google.golang.org/protobuf/encoding/protojson"
)

const (
	policyKey    = "policy"
	toKey        = "to"
	envoyOptsKey = "_envoy_opts"
)

var (
	errKeysMustBeStrings = errors.New("cannot convert nested map: all keys must be strings")
)

var (
	protoPartial = protojson.UnmarshalOptions{AllowPartial: true, DiscardUnknown: true}
)
