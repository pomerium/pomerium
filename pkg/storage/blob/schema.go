package blob

import (
	"fmt"
	"path"

	"github.com/pomerium/pomerium/pkg/storage/blob/middleware"
)

const (
	ContentTypeJSON     = "application/json"
	ContentTypeProtobuf = "application/protobuf"
)

type SchemaV1 struct {
	RecordingType string
	ClusterID     string
}

func (c SchemaV1) ListMiddleware() middleware.ListMiddleware {
	return func(op *middleware.ListOp) error {
		op.Opts.Prefix = c.BasePath() + Separator
		op.Opts.Delimiter = Separator
		return nil
	}
}

type RecordingType string

const (
	RecordingTypeSSH RecordingType = "ssh"
)

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
	return path.Join(c.BasePath(), key+".proto"), ContentTypeProtobuf
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

func (c SchemaV1) Validate() error {
	if c.ClusterID == "" {
		return fmt.Errorf("no cluster ID")
	}
	if c.RecordingType == "" {
		return fmt.Errorf("no recording type")
	}
	return nil
}

type SchemaV1WithKey struct {
	SchemaV1
	Key string
}

func (c SchemaV1WithKey) Validate() error {
	if err := c.SchemaV1.Validate(); err != nil {
		return fmt.Errorf("invalid base schema : %w", err)
	}
	if c.Key == "" {
		return fmt.Errorf("empty key")
	}
	return nil
}

func NewSchemaV1WithKey(base SchemaV1, key string) SchemaV1WithKey {
	return SchemaV1WithKey{SchemaV1: base, Key: key}
}

func (c SchemaV1WithKey) MetadataPath() (fullPath string, contentType string) {
	return c.SchemaV1.MetadataPath(c.Key)
}

func (c SchemaV1WithKey) MetadataJSON() (fullPath string, contentType string) {
	return c.SchemaV1.MetadataJSON(c.Key)
}

func (c SchemaV1WithKey) ObjectPath() string {
	return c.SchemaV1.ObjectPath(c.Key)
}

func (c SchemaV1WithKey) ManifestPath() (fullPath string, contentType string) {
	return c.SchemaV1.ManifestPath(c.Key)
}

func (c SchemaV1WithKey) SignaturePath() (key string, contentType string) {
	return c.SchemaV1.SignaturePath(c.Key)
}

func (c SchemaV1WithKey) ChunkPath(id chunkID) (fullPath string, contentType string) {
	return c.SchemaV1.ChunkPath(c.Key, id)
}
