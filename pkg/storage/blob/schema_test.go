// !! Tests in this file are meant to guard against breaking changes. Edit with caution!
package blob_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/pomerium/pomerium/pkg/storage/blob"
)

func TestSchemaV1_BasePath(t *testing.T) {
	t.Parallel()
	s := blob.SchemaV1{ClusterID: "cluster-1", RecordingType: "ssh"}
	assert.Equal(t, "cluster-1/ssh", s.BasePath())
}

func TestSchemaV1_ObjectPath(t *testing.T) {
	t.Parallel()
	s := blob.SchemaV1{ClusterID: "c1", RecordingType: "ssh"}
	assert.Equal(t, "c1/ssh/rec-42", s.ObjectPath("rec-42"))
}

func TestSchemaV1_MetadataPath(t *testing.T) {
	t.Parallel()
	s := blob.SchemaV1{ClusterID: "c1", RecordingType: "ssh"}

	p, ct := s.MetadataPath("rec-1")
	assert.Equal(t, "c1/ssh/rec-1.proto", p)
	assert.Equal(t, blob.ContentTypeProtobuf, ct)
}

func TestSchemaV1_MetadataJSON(t *testing.T) {
	t.Parallel()
	s := blob.SchemaV1{ClusterID: "c1", RecordingType: "ssh"}

	p, ct := s.MetadataJSON("rec-1")
	assert.Equal(t, "c1/ssh/rec-1.json", p)
	assert.Equal(t, blob.ContentTypeJSON, ct)
}

func TestSchemaV1_ManifestPath(t *testing.T) {
	t.Parallel()
	s := blob.SchemaV1{ClusterID: "c1", RecordingType: "ssh"}

	p, ct := s.ManifestPath("rec-1")
	assert.Equal(t, "c1/ssh/rec-1/manifest", p)
	assert.Equal(t, blob.ContentTypeProtobuf, ct)
}

func TestSchemaV1_SignaturePath(t *testing.T) {
	t.Parallel()
	s := blob.SchemaV1{ClusterID: "c1", RecordingType: "ssh"}

	p, ct := s.SignaturePath("rec-1")
	assert.Equal(t, "c1/ssh/rec-1.sig", p)
	assert.Equal(t, blob.ContentTypeProtobuf, ct)
}

func TestSchemaV1_ChunkPath(t *testing.T) {
	t.Parallel()
	s := blob.SchemaV1{ClusterID: "c1", RecordingType: "ssh"}

	p, ct := s.ChunkPath("rec-1", 0)
	assert.Equal(t, "c1/ssh/rec-1/0000000000", p)
	assert.Equal(t, blob.ContentTypeProtobuf, ct)

	p, _ = s.ChunkPath("rec-1", 42)
	assert.Equal(t, "c1/ssh/rec-1/0000000042", p)
}

func TestAsIDStr(t *testing.T) {
	t.Parallel()
	assert.Equal(t, "0000000000", blob.AsIDStr(0))
	assert.Equal(t, "0000000001", blob.AsIDStr(1))
	assert.Equal(t, "0000000042", blob.AsIDStr(42))
	assert.Equal(t, "9999999999", blob.AsIDStr(9999999999))
}

func TestSchemaV1WithKey(t *testing.T) {
	t.Parallel()
	base := blob.SchemaV1{ClusterID: "c1", RecordingType: "ssh"}
	s := blob.NewSchemaV1WithKey(base, "rec-1")

	assert.Equal(t, "c1/ssh/rec-1", s.ObjectPath())

	p, ct := s.MetadataPath()
	assert.Equal(t, "c1/ssh/rec-1.proto", p)
	assert.Equal(t, blob.ContentTypeProtobuf, ct)

	p, ct = s.MetadataJSON()
	assert.Equal(t, "c1/ssh/rec-1.json", p)
	assert.Equal(t, blob.ContentTypeJSON, ct)

	p, ct = s.ManifestPath()
	assert.Equal(t, "c1/ssh/rec-1/manifest", p)
	assert.Equal(t, blob.ContentTypeProtobuf, ct)

	p, ct = s.SignaturePath()
	assert.Equal(t, "c1/ssh/rec-1.sig", p)
	assert.Equal(t, blob.ContentTypeProtobuf, ct)

	p, ct = s.ChunkPath(5)
	assert.Equal(t, "c1/ssh/rec-1/0000000005", p)
	assert.Equal(t, blob.ContentTypeProtobuf, ct)
}

func TestSchemaV1_EmptyFields(t *testing.T) {
	t.Parallel()
	s := blob.SchemaV1{}

	assert.Equal(t, "", s.BasePath())
	assert.Equal(t, "key", s.ObjectPath("key"))

	p, _ := s.ChunkPath("key", 0)
	assert.Equal(t, "key/0000000000", p)
}
