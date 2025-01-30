package filemgr

import (
	"fmt"
	"path/filepath"

	"github.com/martinlindhe/base36"
	"github.com/zeebo/xxh3"
)

// GetFileNameWithBytesHash constructs a filename using a base filename and a hash of
// the data. For example: GetFileNameWithBytesHash("example.txt", []byte{...}) ==> "example-abcd1234.txt"
func GetFileNameWithBytesHash(base string, data []byte) string {
	h := xxh3.Hash(data)
	he := base36.Encode(h)
	ext := filepath.Ext(base)
	return fmt.Sprintf("%s-%x%s", base[:len(base)-len(ext)], he, ext)
}
