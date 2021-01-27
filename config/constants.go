package config

import (
	"errors"

	"github.com/mitchellh/mapstructure"
	"github.com/spf13/viper"
	"google.golang.org/protobuf/encoding/protojson"
)

const (
	policyKey    = "policy"
	toKey        = "to"
	envoyOptsKey = "_envoy_opts"
)

var (
	errKeysMustBeStrings       = errors.New("cannot convert nested map: all keys must be strings")
	errZeroWeight              = errors.New("zero load balancing weight not permitted")
	errEndpointWeightsSpec     = errors.New("either no weights should be provided, or all endpoints must have non-zero weight specified")
	errHostnameMustBeSpecified = errors.New("endpoint hostname must be specified")
	errSchemeMustBeSpecified   = errors.New("url scheme must be provided")
	errMalformedPolicy         = errors.New("policy syntax error")
)

var (
	protoPartial = protojson.UnmarshalOptions{AllowPartial: true, DiscardUnknown: true}
)

var (
	viperPolicyHooks = viper.DecodeHook(mapstructure.ComposeDecodeHookFunc(
		mapstructure.StringToTimeDurationHookFunc(),
		mapstructure.StringToSliceHookFunc(","),
		DecodePolicyHookFunc(),
	))
)
