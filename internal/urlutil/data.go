package urlutil

import (
	"encoding/base64"
)

// DataURL returns a data-url for the data.
func DataURL(mediaType string, data []byte) string {
	bs := base64.StdEncoding.EncodeToString(data)
	return "data:" + mediaType + ";base64," + bs
}
