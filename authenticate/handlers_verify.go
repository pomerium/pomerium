package authenticate

import (
	"encoding/json"
	"net/http"

	"github.com/pomerium/pomerium/internal/httputil"
	"github.com/pomerium/pomerium/internal/log"
)

type VerifyAccessTokenRequest struct {
	AccessToken        string `json:"accessToken"`
	IdentityProviderID string `json:"identityProviderId,omitempty"`
}

type VerifyIdentityTokenRequest struct {
	IdentityToken      string `json:"identityToken"`
	IdentityProviderID string `json:"identityProviderId,omitempty"`
}

type VerifyTokenResponse struct {
	Valid  bool           `json:"valid"`
	Claims map[string]any `json:"claims,omitempty"`
}

func (a *Authenticate) verifyAccessToken(w http.ResponseWriter, r *http.Request) error {
	var req VerifyAccessTokenRequest
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		return httputil.NewError(http.StatusBadRequest, err)
	}

	authenticator, err := a.cfg.getIdentityProvider(r.Context(), a.tracerProvider, a.options.Load(), req.IdentityProviderID)
	if err != nil {
		return err
	}

	var res VerifyTokenResponse
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
	var req VerifyIdentityTokenRequest
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		return httputil.NewError(http.StatusBadRequest, err)
	}

	authenticator, err := a.cfg.getIdentityProvider(r.Context(), a.tracerProvider, a.options.Load(), req.IdentityProviderID)
	if err != nil {
		return err
	}

	var res VerifyTokenResponse
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
