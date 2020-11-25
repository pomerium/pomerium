package encoding

import (
	"encoding/base64"
	"encoding/json"
	"strings"
)

// DecodeBase64OrJSON decodes a JSON string that can optionally be base64 encoded.
func DecodeBase64OrJSON(in string, out interface{}) error {
	in = strings.TrimSpace(in)

	// the service account can be base64 encoded
	if !strings.HasPrefix(in, "{") {
		bs, err := base64.StdEncoding.DecodeString(in)
		if err != nil {
			return err
		}
		in = string(bs)
	}

	return json.Unmarshal([]byte(in), out)
}
