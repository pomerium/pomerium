package authenticate

import (
	"encoding/json"
	"net/http"

	"github.com/pomerium/pomerium/internal/httputil"
	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/pkg/authenticateapi"
)

func (a *Authenticate) verifyAccessToken(w http.ResponseWriter, r *http.Request) error {
	var req authenticateapi.VerifyAccessTokenRequest
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		return httputil.NewError(http.StatusBadRequest, err)
	}

	authenticator, err := a.cfg.getIdentityProvider(a.options.Load(), req.IdentityProviderID)
	if err != nil {
		return err
	}

	var res authenticateapi.VerifyTokenResponse
	claims, err := authenticator.VerifyAccessToken(r.Context(), req.AccessToken)
	if err == nil {
		res.Valid = true
		res.Claims = claims
	} else {
		res.Valid = false
		log.Ctx(r.Context()).Info().
			Err(err).
			Str("idp", authenticator.Name()).
			Msg("access token failed verification")
	}

	err = json.NewEncoder(w).Encode(&res)
	if err != nil {
		return err
	}

	return nil
}

func (a *Authenticate) verifyIdentityToken(w http.ResponseWriter, r *http.Request) error {
	var req authenticateapi.VerifyIdentityTokenRequest
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		return httputil.NewError(http.StatusBadRequest, err)
	}

	authenticator, err := a.cfg.getIdentityProvider(a.options.Load(), req.IdentityProviderID)
	if err != nil {
		return err
	}

	var res authenticateapi.VerifyTokenResponse
	claims, err := authenticator.VerifyIdentityToken(r.Context(), req.IdentityToken)
	if err == nil {
		res.Valid = true
		res.Claims = claims
	} else {
		res.Valid = false
		log.Ctx(r.Context()).Info().
			Err(err).
			Str("idp", authenticator.Name()).
			Msg("identity token failed verification")
	}

	err = json.NewEncoder(w).Encode(&res)
	if err != nil {
		return err
	}

	return nil
}
