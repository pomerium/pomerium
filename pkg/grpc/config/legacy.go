package config

import (
	envoy_config_cluster_v3 "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
)

// SetEnvoyOpts sets the envoy options field for a route. This field was removed from the
// current protobuf definition, but it used to exist as tag 36 and can be sent as an unknown
// field for older versions of Pomerium.
func (x *Route) SetEnvoyOpts(cluster *envoy_config_cluster_v3.Cluster) error {
	return marshalUnknownField(x, 36, cluster)
}

func marshalUnknownField(dst proto.Message, fieldNumber protowire.Number, src proto.Message) error {
	bs, err := (&proto.MarshalOptions{
		AllowPartial:  true,
		Deterministic: true,
	}).Marshal(src)
	if err != nil {
		return err
	}
	unknown := dst.ProtoReflect().GetUnknown()
	unknown = protowire.AppendTag(unknown, fieldNumber, protowire.BytesType)
	unknown = protowire.AppendBytes(unknown, bs)
	dst.ProtoReflect().SetUnknown(unknown)
	return nil
}
