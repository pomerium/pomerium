package blob

import (
	"fmt"
	"path"
)

type schemaV1 struct {
	globalPrefix   string
	recordingType  string
	installationId string
}

func asIDStr(cID chunkID) string {
	return fmt.Sprintf("%010d", cID)
}

func (c *schemaV1) basePath() string {
	if c.installationId == "" {
		return path.Join(c.globalPrefix, c.recordingType, noInstallationID)
	}
	return path.Join(c.globalPrefix, c.recordingType, c.installationId)
}

func (c *schemaV1) metadataPath(key string) string {
	return path.Join(c.basePath(), key+".attrs")
}

func (c *schemaV1) manifestPath(key string) string {
	return path.Join(c.basePath(), key, "manifest")
}

func (c *schemaV1) chunkPath(key string, id chunkID) string {
	return path.Join(c.basePath(), key, asIDStr(id))
}

type schemaV1WithKey struct {
	*schemaV1
	key string
}

func (c *schemaV1WithKey) manifestPath() string {
	return c.schemaV1.manifestPath(c.key)
}

func (c *schemaV1WithKey) chunkPath(id chunkID) string {
	return c.schemaV1.chunkPath(c.key, id)
}
