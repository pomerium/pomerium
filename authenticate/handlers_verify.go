package authenticate

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/pomerium/pomerium/internal/httputil"
	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/pkg/authenticateapi"
)

func (a *Authenticate) verifyAccessToken(w http.ResponseWriter, r *http.Request) error {
	start := time.Now()

	a.accessTokenVerificationCount.Add(r.Context(), 1)

	var req authenticateapi.VerifyAccessTokenRequest
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		return httputil.NewError(http.StatusBadRequest, err)
	}

	authenticator, err := a.cfg.getIdentityProvider(r.Context(), a.tracerProvider, a.options.Load(), req.IdentityProviderID)
	if err != nil {
		return err
	}

	var res authenticateapi.VerifyTokenResponse
	claims, err := authenticator.VerifyAccessToken(r.Context(), req.AccessToken)
	if err == nil {
		a.accessTokenValidVerificationCount.Add(r.Context(), 1)
		res.Valid = true
		res.Claims = claims
	} else {
		a.accessTokenInvalidVerificationCount.Add(r.Context(), 1)
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

	a.accessTokenVerificationDuration.Record(r.Context(), time.Since(start).Milliseconds())

	return nil
}

func (a *Authenticate) verifyIdentityToken(w http.ResponseWriter, r *http.Request) error {
	start := time.Now()

	a.identityTokenVerificationCount.Add(r.Context(), 1)

	var req authenticateapi.VerifyIdentityTokenRequest
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		return httputil.NewError(http.StatusBadRequest, err)
	}

	authenticator, err := a.cfg.getIdentityProvider(r.Context(), a.tracerProvider, a.options.Load(), req.IdentityProviderID)
	if err != nil {
		return err
	}

	var res authenticateapi.VerifyTokenResponse
	claims, err := authenticator.VerifyIdentityToken(r.Context(), req.IdentityToken)
	if err == nil {
		a.identityTokenValidVerificationCount.Add(r.Context(), 1)
		res.Valid = true
		res.Claims = claims
	} else {
		a.identityTokenInvalidVerificationCount.Add(r.Context(), 1)
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

	a.identityTokenVerificationDuration.Record(r.Context(), time.Since(start).Milliseconds())

	return nil
}
