package handlers

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"hash/fnv"
	"net/http"
	"strconv"
	"time"

	"github.com/rs/cors"

	"github.com/pomerium/pomerium/internal/httputil"
	"github.com/pomerium/pomerium/pkg/cryptutil"
)

// JWKSHandler returns the /.well-known/pomerium/jwks.json handler.
func JWKSHandler(
	rawSigningKey string,
	additionalKeys ...any,
) http.Handler {
	return cors.AllowAll().Handler(httputil.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		var jwks struct {
			Keys []any `json:"keys"`
		}
		if rawSigningKey != "" {
			decodedCert, err := base64.StdEncoding.DecodeString(rawSigningKey)
			if err != nil {
				return httputil.NewError(http.StatusInternalServerError, errors.New("bad base64 encoding for signing key"))
			}
			jwk, err := cryptutil.PublicJWKFromBytes(decodedCert)
			if err != nil {
				return httputil.NewError(http.StatusInternalServerError, errors.New("bad signing key"))
			}
			jwks.Keys = append(jwks.Keys, *jwk)
		}
		jwks.Keys = append(jwks.Keys, additionalKeys...)

		bs, err := json.Marshal(jwks)
		if err != nil {
			return err
		}

		hasher := fnv.New64()
		_, _ = hasher.Write(bs)
		h := hasher.Sum64()

		w.Header().Set("Cache-Control", "max-age=60")
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Length", strconv.Itoa(len(bs)))
		w.Header().Set("ETag", fmt.Sprintf(`"%x"`, h))
		http.ServeContent(w, r, "jwks.json", time.Time{}, bytes.NewReader(bs))
		return nil
	}))
}
