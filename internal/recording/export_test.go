package recording

import (
	gblob "gocloud.dev/blob"
)

// LoadStreamConfigForTest checks internal fields on the server to make sure config
// reload correctly propagates config changes
func LoadStreamConfigForTest(s Server) (bucket *gblob.Bucket, prefix string, err error) {
	recSrv := s.(*recordingServer)
	recSrv.serverMu.Lock()
	defer recSrv.serverMu.Unlock()
	return recSrv.bucket.Load(), recSrv.blobCfg.Load().ManagedPrefix, recSrv.bucketErr
}
