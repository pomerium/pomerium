package handlers

import (
	"encoding/base64"
	"errors"
	"net/http"

	"github.com/go-jose/go-jose/v3"
	"github.com/rs/cors"

	"github.com/pomerium/pomerium/internal/httputil"
	"github.com/pomerium/pomerium/pkg/cryptutil"
)

// JWKSHandler returns the /.well-known/pomerium/jwks.json handler.
func JWKSHandler(rawSigningKey string) http.Handler {
	return cors.AllowAll().Handler(httputil.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		var jwks jose.JSONWebKeySet
		if rawSigningKey != "" {
			decodedCert, err := base64.StdEncoding.DecodeString(rawSigningKey)
			if err != nil {
				return httputil.NewError(http.StatusInternalServerError, errors.New("bad signing key"))
			}
			jwk, err := cryptutil.PublicJWKFromBytes(decodedCert)
			if err != nil {
				return httputil.NewError(http.StatusInternalServerError, errors.New("bad signing key"))
			}
			jwks.Keys = append(jwks.Keys, *jwk)
		}
		httputil.RenderJSON(w, http.StatusOK, jwks)
		return nil
	}))
}
