package config

import (
	"errors"

	"github.com/mitchellh/mapstructure"
	"github.com/spf13/viper"
	"google.golang.org/protobuf/encoding/protojson"

	"github.com/pomerium/pomerium/config/otelconfig"
)

const (
	toKey        = "to"
	envoyOptsKey = "_envoy_opts"
)

var (
	errKeysMustBeStrings                    = errors.New("cannot convert nested map: all keys must be strings")
	errZeroWeight                           = errors.New("zero load balancing weight not permitted")
	errEndpointWeightsSpec                  = errors.New("either no weights should be provided, or all endpoints must have non-zero weight specified")
	errHostnameMustBeSpecified              = errors.New("endpoint hostname must be specified")
	errSchemeMustBeSpecified                = errors.New("url scheme must be provided")
	errEmptyUrls                            = errors.New("url list is empty")
	errEitherToOrRedirectOrResponseRequired = errors.New("policy should have either `to` or `redirect` or `response` defined")
)

var protoPartial = protojson.UnmarshalOptions{AllowPartial: true, DiscardUnknown: true}

// ViperPolicyHooks are used to decode options and policy coming from YAML and env vars
var ViperPolicyHooks = viper.DecodeHook(mapstructure.ComposeDecodeHookFunc(
	mapstructure.StringToTimeDurationHookFunc(),
	mapstructure.StringToSliceHookFunc(","),
	// decode policy including all protobuf-native notations - i.e. duration as `1s`
	// https://developers.google.com/protocol-buffers/docs/proto3#json
	DecodePolicyHookFunc(),
	// parse base-64 encoded POLICY that is bound to environment variable
	DecodePolicyBase64Hook(),
	decodeNullBoolHookFunc(),
	decodeJWTClaimHeadersHookFunc(),
	decodeBearerTokenFormatHookFunc(),
	decodeCodecTypeHookFunc(),
	decodePPLPolicyHookFunc(),
	decodeSANMatcherHookFunc(),
	decodeStringToMapHookFunc(),
	otelconfig.OtelDurationFunc(),
))
