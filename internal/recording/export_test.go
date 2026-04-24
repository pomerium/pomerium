package recording

import (
	gblob "gocloud.dev/blob"
)

// LoadStreamConfigForTest exposes loadStreamConfig to the external
// recording_test package so tests can observe the server's resolved
// bucket/prefix state after config changes without going through a live
// gRPC stream.
func LoadStreamConfigForTest(s Server) (bucket *gblob.Bucket, prefix string, err error) {
	return s.(*recordingServer).loadCurStreamConfig()
}
