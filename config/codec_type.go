package config

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strings"

	envoy_http_connection_manager "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
	"github.com/go-viper/mapstructure/v2"

	configpb "github.com/pomerium/pomerium/pkg/grpc/config"
)

// The CodecType specifies which codec to use for downstream connections.
type CodecType string

// CodecTypes
const (
	CodecTypeUnset CodecType = ""
	CodecTypeAuto  CodecType = "auto"
	CodecTypeHTTP1 CodecType = "http1"
	CodecTypeHTTP2 CodecType = "http2"
	CodecTypeHTTP3 CodecType = "http3"
)

// ParseCodecType parses the codec type.
func ParseCodecType(raw string) (CodecType, error) {
	switch CodecType(strings.TrimSpace(strings.ToLower(raw))) {
	case CodecTypeAuto:
		return CodecTypeAuto, nil
	case CodecTypeHTTP1:
		return CodecTypeHTTP1, nil
	case CodecTypeHTTP2:
		return CodecTypeHTTP2, nil
	case CodecTypeHTTP3:
		return CodecTypeHTTP3, nil
	}
	return CodecTypeAuto, fmt.Errorf("invalid codec type: %s", raw)
}

// CodecTypeFromProto converts a proto codec type into a config codec type.
func CodecTypeFromProto(src configpb.CodecType) CodecType {
	switch src {
	case configpb.CodecType_CODEC_TYPE_HTTP1:
		return CodecTypeHTTP1
	case configpb.CodecType_CODEC_TYPE_HTTP2:
		return CodecTypeHTTP2
	case configpb.CodecType_CODEC_TYPE_HTTP3:
		return CodecTypeHTTP3
	}
	return CodecTypeAuto
}

// ToEnvoy converts the codec type to an envoy codec type.
func (codecType CodecType) ToEnvoy() envoy_http_connection_manager.HttpConnectionManager_CodecType {
	switch codecType {
	case CodecTypeHTTP1:
		return envoy_http_connection_manager.HttpConnectionManager_HTTP1
	case CodecTypeHTTP2:
		return envoy_http_connection_manager.HttpConnectionManager_HTTP2
	case CodecTypeHTTP3:
		return envoy_http_connection_manager.HttpConnectionManager_HTTP3
	}
	return envoy_http_connection_manager.HttpConnectionManager_AUTO
}

// ToProto converts the codec type to a proto codec type.
func (codecType CodecType) ToProto() configpb.CodecType {
	switch codecType {
	case CodecTypeHTTP1:
		return configpb.CodecType_CODEC_TYPE_HTTP1
	case CodecTypeHTTP2:
		return configpb.CodecType_CODEC_TYPE_HTTP2
	case CodecTypeHTTP3:
		return configpb.CodecType_CODEC_TYPE_HTTP3
	}
	return configpb.CodecType_CODEC_TYPE_AUTO
}

func decodeCodecTypeHookFunc() mapstructure.DecodeHookFunc {
	return func(_, t reflect.Type, data any) (any, error) {
		if t != reflect.TypeOf(CodecType("")) {
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
		return ParseCodecType(raw)
	}
}
