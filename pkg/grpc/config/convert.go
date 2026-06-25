package config

import (
	envoy_config_cluster_v3 "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	envoy_config_core_v3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	envoy_http_connection_manager "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
	"google.golang.org/protobuf/proto"
)

func (x CodecType) ToEnvoy() envoy_http_connection_manager.HttpConnectionManager_CodecType {
	switch x {
	case CodecType_CODEC_TYPE_HTTP1:
		return envoy_http_connection_manager.HttpConnectionManager_HTTP1
	case CodecType_CODEC_TYPE_HTTP2:
		return envoy_http_connection_manager.HttpConnectionManager_HTTP2
	case CodecType_CODEC_TYPE_HTTP3:
		return envoy_http_connection_manager.HttpConnectionManager_HTTP3
	default:
		return envoy_http_connection_manager.HttpConnectionManager_AUTO
	}
}

// The Pomerium enum reserves 0 for UNKNOWN, so its numeric values are offset
// by one from Envoy's enum. An explicit switch avoids a silent miscast.
func (x HeadersWithUnderscoresAction) ToEnvoy() envoy_config_core_v3.HttpProtocolOptions_HeadersWithUnderscoresAction {
	switch x {
	case HeadersWithUnderscoresAction_HEADERS_WITH_UNDERSCORES_ACTION_ALLOW:
		return envoy_config_core_v3.HttpProtocolOptions_ALLOW
	case HeadersWithUnderscoresAction_HEADERS_WITH_UNDERSCORES_ACTION_REJECT_REQUEST:
		return envoy_config_core_v3.HttpProtocolOptions_REJECT_REQUEST
	case HeadersWithUnderscoresAction_HEADERS_WITH_UNDERSCORES_ACTION_DROP_HEADER:
		return envoy_config_core_v3.HttpProtocolOptions_DROP_HEADER
	default:
		return envoy_config_core_v3.HttpProtocolOptions_ALLOW
	}
}

func (x PathWithEscapedSlashesAction) ToEnvoy() envoy_http_connection_manager.HttpConnectionManager_PathWithEscapedSlashesAction {
	switch x {
	case PathWithEscapedSlashesAction_PATH_WITH_ESCAPED_SLASHES_ACTION_KEEP_UNCHANGED:
		return envoy_http_connection_manager.HttpConnectionManager_KEEP_UNCHANGED
	case PathWithEscapedSlashesAction_PATH_WITH_ESCAPED_SLASHES_ACTION_REJECT_REQUEST:
		return envoy_http_connection_manager.HttpConnectionManager_REJECT_REQUEST
	case PathWithEscapedSlashesAction_PATH_WITH_ESCAPED_SLASHES_ACTION_UNESCAPE_AND_REDIRECT:
		return envoy_http_connection_manager.HttpConnectionManager_UNESCAPE_AND_REDIRECT
	case PathWithEscapedSlashesAction_PATH_WITH_ESCAPED_SLASHES_ACTION_UNESCAPE_AND_FORWARD:
		return envoy_http_connection_manager.HttpConnectionManager_UNESCAPE_AND_FORWARD
	default:
		return envoy_http_connection_manager.HttpConnectionManager_IMPLEMENTATION_SPECIFIC_DEFAULT
	}
}

func (x *HealthCheck) ToEnvoy() *envoy_config_core_v3.HealthCheck {
	return protoToProto[envoy_config_core_v3.HealthCheck](x)
}

func (x *OutlierDetection) ToEnvoy() *envoy_config_cluster_v3.OutlierDetection {
	return protoToProto[envoy_config_cluster_v3.OutlierDetection](x)
}

func (x *LoadBalancingPolicy) ToEnvoy() envoy_config_cluster_v3.Cluster_LbPolicy {
	if x == nil {
		return 0
	}
	switch *x {
	case LoadBalancingPolicy_LOAD_BALANCING_POLICY_MAGLEV:
		return envoy_config_cluster_v3.Cluster_MAGLEV
	case LoadBalancingPolicy_LOAD_BALANCING_POLICY_RANDOM:
		return envoy_config_cluster_v3.Cluster_RANDOM
	case LoadBalancingPolicy_LOAD_BALANCING_POLICY_RING_HASH:
		return envoy_config_cluster_v3.Cluster_RING_HASH
	case LoadBalancingPolicy_LOAD_BALANCING_POLICY_LEAST_REQUEST:
		return envoy_config_cluster_v3.Cluster_LEAST_REQUEST
	default:
		return envoy_config_cluster_v3.Cluster_ROUND_ROBIN
	}
}

func protoToProto[T any, TMsg interface {
	*T
	proto.Message
}](src proto.Message) TMsg {
	if src == nil {
		return nil
	}

	var dst T
	proto.Reset(TMsg(&dst))
	b, err := (&proto.MarshalOptions{AllowPartial: true}).Marshal(src)
	if err != nil {
		panic(err)
	}
	err = (&proto.UnmarshalOptions{
		AllowPartial: true,
	}).Unmarshal(b, TMsg(&dst))
	if err != nil {
		panic(err)
	}
	return TMsg(&dst)
}
