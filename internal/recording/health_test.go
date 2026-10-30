package recording

import (
	"testing"

	"github.com/stretchr/testify/assert"
	gblob "gocloud.dev/blob"

	"github.com/pomerium/pomerium/pkg/storage/blob"
)

func TestRecordingServerHealth(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name    string
		serving bool
		cfg     *blob.StorageConfig
		bucket  *gblob.Bucket
		ok      bool
	}{
		{"not_serving", false, &blob.StorageConfig{}, &gblob.Bucket{}, false},
		{"no_config", true, nil, nil, false},
		{"no_bucket", true, &blob.StorageConfig{}, nil, false},
		{"serving", true, &blob.StorageConfig{}, &gblob.Bucket{}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			r := &recordingServer{}
			r.serving.Store(tc.serving)
			r.blobCfg.Store(tc.cfg)
			r.bucket.Store(tc.bucket)

			ready, _ := r.Ready(t.Context())
			assert.Equal(t, tc.ok, ready)
			healthy, _ := r.Healthy(t.Context())
			assert.Equal(t, tc.ok, healthy)
		})
	}
}
