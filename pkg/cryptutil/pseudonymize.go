package cryptutil

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"io"
)

// Pseudonymize pseudonymizes data by computing the HMAC-SHA256 of the data.
func Pseudonymize(organizationID string, data string) string {
	h := hmac.New(sha256.New, []byte(organizationID))
	_, _ = io.WriteString(h, data)
	bs := h.Sum(nil)
	return base64.StdEncoding.EncodeToString(bs)
}
