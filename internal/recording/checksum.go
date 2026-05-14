package recording

//nolint:gosec
import "crypto/md5"

func checkMd5(expectedChecksum [16]byte, data []byte) bool {
	//nolint:gosec
	actual := md5.Sum(data)
	return actual == expectedChecksum
}
