// Package handlers provides http handlers for HPKE.
package handlers

import (
	"bytes"
	"fmt"
	"hash/fnv"
	"net/http"
	"strconv"
	"time"

	"github.com/rs/cors"

	"github.com/pomerium/pomerium/internal/httputil"
	"github.com/pomerium/pomerium/internal/urlutil"
	"github.com/pomerium/pomerium/pkg/hpke"
)

// HPKEPublicKeyPath is the path to the HPKE public key.
const HPKEPublicKeyPath = urlutil.HPKEPublicKeyPath

// HPKEPublicKeyHandler returns a handler which returns the HPKE public key.
func HPKEPublicKeyHandler(publicKey *hpke.PublicKey) http.Handler {
	return cors.AllowAll().Handler(httputil.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		bs := publicKey.Bytes()

		hasher := fnv.New64()
		_, _ = hasher.Write(bs)
		h := hasher.Sum64()

		w.Header().Set("Cache-Control", "max-age=60")
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Length", strconv.Itoa(len(bs)))
		w.Header().Set("ETag", fmt.Sprintf(`"%x"`, h))
		http.ServeContent(w, r, "hpke-public-key", time.Time{}, bytes.NewReader(bs))
		return nil
	}))
}
