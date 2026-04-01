package envoyversion

import (
	"strconv"
	"strings"
	"time"

	v1 "github.com/opencontainers/image-spec/specs-go/v1"
)

type Lockfile struct {
	// Output filename
	Filename string `json:"filename"`
	// Decompressed size
	Size int64 `json:"size"`
	// Digest of the decompressed file. This is not an OCI CAS digest.
	Digest string `json:"digest"`
	// Go mod version string
	Version string `json:"version"`
	// Remote manifest descriptor
	ManifestDescriptor v1.Descriptor `json:"manifest_descriptor"`
	// Labels from the ImageConfig referenced in the manifest
	Labels map[string]string `json:"labels"`
}

func (lf Lockfile) SourceRepo() string {
	return strings.TrimSuffix(strings.TrimPrefix(lf.Labels["BUILD_SCM_REMOTE"], "https://"), ".git")
}

func (lf Lockfile) GitCommit() string {
	return lf.Labels["BUILD_SCM_REVISION"]
}

func (lf Lockfile) BuildTimestamp() time.Time {
	unix, err := strconv.ParseInt(lf.Labels["BUILD_TIMESTAMP"], 10, 64)
	if err != nil {
		return time.Time{}
	}
	return time.Unix(unix, 0)
}
