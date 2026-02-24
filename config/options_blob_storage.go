package config

import (
	configpb "github.com/pomerium/pomerium/pkg/grpc/config"
	"github.com/pomerium/pomerium/pkg/storage/blob"
)

// BlobStorageFromProto sets blob storage options from a protobuf message.
func BlobStorageFromProto(src *configpb.BlobStorageSettings) *blob.StorageConfig {
	if src == nil {
		return nil
	}
	cfg := &blob.StorageConfig{}
	if src.BucketUri != nil {
		cfg.BucketURI = *src.BucketUri
	}
	if src.ManagedPrefix != nil {
		cfg.ManagedPrefix = *src.ManagedPrefix
	}
	return cfg
}

// BlobStorageToProto converts a blob storage config to a protobuf message.
func BlobStorageToProto(cfg *blob.StorageConfig) *configpb.BlobStorageSettings {
	if cfg == nil {
		return nil
	}
	pb := &configpb.BlobStorageSettings{}
	if cfg.BucketURI != "" {
		pb.BucketUri = &cfg.BucketURI
	}
	if cfg.ManagedPrefix != "" {
		pb.ManagedPrefix = &cfg.ManagedPrefix
	}
	return pb
}
