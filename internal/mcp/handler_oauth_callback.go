package mcp

import (
	"fmt"
	"net/http"

	"golang.org/x/oauth2"
	"golang.org/x/sync/errgroup"

	"github.com/pomerium/pomerium/internal/log"
	oauth21proto "github.com/pomerium/pomerium/internal/oauth21/gen"
)

func (srv *Handler) OAuthCallback(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	code := r.URL.Query().Get("code")
	authReqID := r.URL.Query().Get("state")
	if code == "" || authReqID == "" {
		http.Error(w, "Invalid callback request: missing code or state", http.StatusBadRequest)
		return
	}

	var token *oauth2.Token
	var authReq *oauth21proto.AuthorizationRequest

	{
		eg, ctx := errgroup.WithContext(ctx)
		eg.Go(func() error {
			var err error
			token, err = srv.relyingParties.CodeExchangeForHost(ctx, r.Host, code)
			if err != nil {
				return fmt.Errorf("oauth2: failed to exchange code: %w", err)
			}
			return nil
		})
		eg.Go(func() error {
			var err error
			authReq, err = srv.storage.GetAuthorizationRequest(ctx, authReqID)
			if err != nil {
				return fmt.Errorf("failed to get authorization request: %w", err)
			}

			return nil
		})

		err := eg.Wait()
		if err != nil {
			log.Ctx(ctx).Error().Err(err).Msg("failed to exchange code")
			http.Error(w, "Failed to exchange code", http.StatusInternalServerError)
			return
		}
	}

	err := srv.storage.StoreUpstreamOAuth2Token(ctx, authReq.UserId, r.Host, OAuth2TokenToPB(token))
	if err != nil {
		log.Ctx(ctx).Error().Err(err).Msg("failed to store upstream oauth2 token")
		http.Error(w, "Failed to store upstream oauth2 token", http.StatusInternalServerError)
		return
	}

	srv.AuthorizationResponse(ctx, w, r, authReqID, authReq)
}
