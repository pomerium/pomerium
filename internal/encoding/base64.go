package encoding

import (
	"encoding/base64"
	"encoding/json"
	"strings"
)

// DecodeBase64OrJSON decodes a JSON string that can optionally be base64 encoded.
func DecodeBase64OrJSON(in string, out any) error {
	in = strings.TrimSpace(in)

	// the data can be base64 encoded
	if !json.Valid([]byte(in)) {
		bs, err := base64.StdEncoding.DecodeString(in)
		if err != nil {
			return err
		}
		in = string(bs)
	}

	return json.Unmarshal([]byte(in), out)
}
