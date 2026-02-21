package blob

import (
	"fmt"
	"path"

	"github.com/pomerium/pomerium/config"
)

const (
	ContentTypeJSON     = "application/json"
	ContentTypeProtobuf = "application/protobuf"
)

type SchemaV1 struct {
	RecordingType string
	ClusterID     string
}

type RecordingType string

const (
	RecordingTypeSSH RecordingType = "ssh"
)

func NewSchemaFromBlobOptions(_ *config.Options, recType RecordingType) (SchemaV1, error) {
	return SchemaV1{
		RecordingType: string(recType),
	}, fmt.Errorf("not yet implemented")
}

func AsIDStr(cID chunkID) string {
	return fmt.Sprintf("%010d", cID)
}

func (c SchemaV1) BasePath() string {
	return path.Join(c.ClusterID, c.RecordingType)
}

func (c SchemaV1) ObjectPath(key string) string {
	return path.Join(c.BasePath(), key)
}

func (c SchemaV1) MetadataJSON(key string) (fullPath string, contentType string) {
	return path.Join(c.BasePath(), key+".json"), ContentTypeJSON
}

func (c SchemaV1) MetadataPath(key string) (fullPath string, contentType string) {
	return path.Join(c.BasePath(), key+".attrs"), ContentTypeProtobuf
}

func (c SchemaV1) ManifestPath(key string) (fullPath string, contentType string) {
	return path.Join(c.BasePath(), key, "manifest"), ContentTypeProtobuf
}

func (c SchemaV1) SignaturePath(key string) (fullPath string, contentType string) {
	return path.Join(c.BasePath(), key+".sig"), ContentTypeProtobuf
}

func (c SchemaV1) ChunkPath(key string, id chunkID) (fullPath string, contentType string) {
	return path.Join(c.BasePath(), key, AsIDStr(id)), ContentTypeProtobuf
}

type SchemaV1WithKey struct {
	SchemaV1
	key string
}

func NewSchemaV1WithKey(base SchemaV1, key string) SchemaV1WithKey {
	return SchemaV1WithKey{SchemaV1: base, key: key}
}

func (c SchemaV1WithKey) MetadataPath() (fullPath string, contentType string) {
	return c.SchemaV1.MetadataPath(c.key)
}

func (c SchemaV1WithKey) MetadataJSON() (fullPath string, contentType string) {
	return c.SchemaV1.MetadataJSON(c.key)
}

func (c SchemaV1WithKey) ObjectPath() string {
	return c.SchemaV1.ObjectPath(c.key)
}

func (c SchemaV1WithKey) ManifestPath() (fullPath string, contentType string) {
	return c.SchemaV1.ManifestPath(c.key)
}

func (c SchemaV1WithKey) SignaturePath() (key string, contentType string) {
	return c.SchemaV1.SignaturePath(c.key)
}

func (c SchemaV1WithKey) ChunkPath(id chunkID) (fullPath string, contentType string) {
	return c.SchemaV1.ChunkPath(c.key, id)
}
