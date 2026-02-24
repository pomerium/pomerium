package config

import (
	configpb "github.com/pomerium/pomerium/pkg/grpc/config"
)

// FromProto sets options from a config settings protobuf.
func (o *RecordingServerConfig) FromProto(src *configpb.RecordingServerSettings) {
	if src == nil {
		return
	}
	if src.Enabled != nil {
		o.Enabled = *src.Enabled
	}
	if src.MaxConcurrentStreams != nil {
		o.MaxConcurrentStreams = int(*src.MaxConcurrentStreams)
	}
	if src.MaxChunkBatchNum != nil {
		o.MaxChunkBatchNum = int(*src.MaxChunkBatchNum)
	}
	if src.MaxChunkSize != nil {
		o.MaxChunkSize = int(*src.MaxChunkSize)
	}
}

// ToProto converts the recording server config to a protobuf message.
func (o *RecordingServerConfig) ToProto() *configpb.RecordingServerSettings {
	if o == nil {
		return nil
	}
	pb := &configpb.RecordingServerSettings{}
	if o.Enabled {
		pb.Enabled = &o.Enabled
	}
	if o.MaxConcurrentStreams != 0 {
		v := int32(o.MaxConcurrentStreams)
		pb.MaxConcurrentStreams = &v
	}
	if o.MaxChunkBatchNum != 0 {
		v := int32(o.MaxChunkBatchNum)
		pb.MaxChunkBatchNum = &v
	}
	if o.MaxChunkSize != 0 {
		v := int32(o.MaxChunkSize)
		pb.MaxChunkSize = &v
	}
	return pb
}
