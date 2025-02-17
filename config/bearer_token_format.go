package config

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strings"

	"github.com/mitchellh/mapstructure"

	configpb "github.com/pomerium/pomerium/pkg/grpc/config"
)

// BearerTokenFormat specifies how bearer tokens are interepreted by Pomerium.
type BearerTokenFormat string

// Bearer Token Formats
const (
	BearerTokenFormatUnknown          BearerTokenFormat = ""
	BearerTokenFormatDefault          BearerTokenFormat = "default"
	BearerTokenFormatIDPAccessToken   BearerTokenFormat = "idp_access_token"
	BearerTokenFormatIDPIdentityToken BearerTokenFormat = "idp_identity_token"
)

// ParseBearerTokenFormat parses the BearerTokenFormat.
func ParseBearerTokenFormat(raw string) (BearerTokenFormat, error) {
	switch BearerTokenFormat(strings.TrimSpace(strings.ToLower(raw))) {
	case BearerTokenFormatUnknown:
		return BearerTokenFormatUnknown, nil
	case BearerTokenFormatDefault:
		return BearerTokenFormatDefault, nil
	case BearerTokenFormatIDPAccessToken:
		return BearerTokenFormatIDPAccessToken, nil
	case BearerTokenFormatIDPIdentityToken:
		return BearerTokenFormatIDPIdentityToken, nil
	}
	return BearerTokenFormatUnknown, fmt.Errorf("invalid bearer token format: %s", raw)
}

func BearerTokenFormatFromPB(pbBearerTokenFormat *configpb.BearerTokenFormat) *BearerTokenFormat {
	if pbBearerTokenFormat == nil {
		return nil
	}

	bearerTokenFormat := new(BearerTokenFormat)
	*bearerTokenFormat = BearerTokenFormatDefault

	switch *pbBearerTokenFormat {
	case configpb.BearerTokenFormat_BEARER_TOKEN_FORMAT_UNKNOWN:
		*bearerTokenFormat = BearerTokenFormatUnknown
	case configpb.BearerTokenFormat_BEARER_TOKEN_FORMAT_DEFAULT:
		*bearerTokenFormat = BearerTokenFormatDefault
	case configpb.BearerTokenFormat_BEARER_TOKEN_FORMAT_IDP_ACCESS_TOKEN:
		*bearerTokenFormat = BearerTokenFormatIDPAccessToken
	case configpb.BearerTokenFormat_BEARER_TOKEN_FORMAT_IDP_IDENTITY_TOKEN:
		*bearerTokenFormat = BearerTokenFormatIDPIdentityToken
	}

	return bearerTokenFormat
}

// ToEnvoy converts the bearer token format into a protobuf enum.
func (bearerTokenFormat *BearerTokenFormat) ToPB() *configpb.BearerTokenFormat {
	if bearerTokenFormat == nil {
		return nil
	}
	switch *bearerTokenFormat {
	case BearerTokenFormatUnknown:
		return configpb.BearerTokenFormat_BEARER_TOKEN_FORMAT_UNKNOWN.Enum()
	case BearerTokenFormatDefault:
		return configpb.BearerTokenFormat_BEARER_TOKEN_FORMAT_DEFAULT.Enum()
	case BearerTokenFormatIDPAccessToken:
		return configpb.BearerTokenFormat_BEARER_TOKEN_FORMAT_IDP_ACCESS_TOKEN.Enum()
	case BearerTokenFormatIDPIdentityToken:
		return configpb.BearerTokenFormat_BEARER_TOKEN_FORMAT_IDP_IDENTITY_TOKEN.Enum()
	default:
		panic(fmt.Sprintf("unknown bearer token format: %v", bearerTokenFormat))
	}
}

func decodeBearerTokenFormatHookFunc() mapstructure.DecodeHookFunc {
	return func(_, t reflect.Type, data any) (any, error) {
		if t != reflect.TypeOf(BearerTokenFormat("")) {
			return data, nil
		}

		bs, err := json.Marshal(data)
		if err != nil {
			return nil, err
		}
		var raw string
		err = json.Unmarshal(bs, &raw)
		if err != nil {
			return nil, err
		}
		return ParseBearerTokenFormat(raw)
	}
}
