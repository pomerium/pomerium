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

	log.Ctx(ctx).Debug().
		Str("method", r.Method).
		Str("host", r.Host).
		Str("path", r.URL.Path).
		Str("query", r.URL.RawQuery).
		Msg("mcp/oauth-callback: request received")

	code := r.URL.Query().Get("code")
	authReqID := r.URL.Query().Get("state")

	log.Ctx(ctx).Debug().
		Bool("has-code", code != "").
		Int("code-length", len(code)).
		Str("auth-req-id", authReqID).
		Msg("mcp/oauth-callback: parsed callback parameters")

	if code == "" || authReqID == "" {
		log.Ctx(ctx).Error().
			Bool("has-code", code != "").
			Bool("has-state", authReqID != "").
			Msg("mcp/oauth-callback: missing code or state parameter")
		http.Error(w, "Invalid callback request: missing code or state", http.StatusBadRequest)
		return
	}

	var token *oauth2.Token
	var authReq *oauth21proto.AuthorizationRequest

	log.Ctx(ctx).Debug().
		Str("host", r.Host).
		Str("auth-req-id", authReqID).
		Msg("mcp/oauth-callback: exchanging code and fetching auth request")

	{
		eg, ctx := errgroup.WithContext(ctx)
		eg.Go(func() error {
			var err error
			log.Ctx(ctx).Debug().Str("host", r.Host).Msg("mcp/oauth-callback: starting code exchange with upstream IdP")
			token, err = srv.hosts.CodeExchangeForHost(ctx, r.Host, code)
			if err != nil {
				return fmt.Errorf("oauth2: failed to exchange code: %w", err)
			}
			log.Ctx(ctx).Debug().
				Bool("has-access-token", token.AccessToken != "").
				Bool("has-refresh-token", token.RefreshToken != "").
				Time("expiry", token.Expiry).
				Msg("mcp/oauth-callback: upstream code exchange successful")
			return nil
		})
		eg.Go(func() error {
			var err error
			log.Ctx(ctx).Debug().Str("auth-req-id", authReqID).Msg("mcp/oauth-callback: fetching authorization request from storage")
			authReq, err = srv.storage.GetAuthorizationRequest(ctx, authReqID)
			if err != nil {
				return fmt.Errorf("failed to get authorization request: %w", err)
			}
			log.Ctx(ctx).Debug().
				Str("auth-req-id", authReqID).
				Str("client-id", authReq.GetClientId()).
				Str("user-id", authReq.GetUserId()).
				Str("session-id", authReq.GetSessionId()).
				Str("redirect-uri", authReq.GetRedirectUri()).
				Msg("mcp/oauth-callback: authorization request retrieved")
			return nil
		})

		err := eg.Wait()
		if err != nil {
			log.Ctx(ctx).Error().Err(err).Msg("mcp/oauth-callback: failed to exchange code or fetch auth request")
			http.Error(w, "Failed to exchange code", http.StatusInternalServerError)
			return
		}
	}

	log.Ctx(ctx).Debug().
		Str("host", r.Host).
		Str("user-id", authReq.UserId).
		Bool("has-access-token", token.AccessToken != "").
		Bool("has-refresh-token", token.RefreshToken != "").
		Msg("mcp/oauth-callback: storing upstream OAuth2 token")

	err := srv.storage.StoreUpstreamOAuth2Token(ctx, r.Host, authReq.UserId, OAuth2TokenToPB(token))
	if err != nil {
		log.Ctx(ctx).Error().Err(err).Msg("mcp/oauth-callback: failed to store upstream oauth2 token")
		http.Error(w, "Failed to store upstream oauth2 token", http.StatusInternalServerError)
		return
	}

	log.Ctx(ctx).Debug().
		Str("host", r.Host).
		Str("user-id", authReq.UserId).
		Msg("mcp/oauth-callback: upstream token stored, proceeding to authorization response")

	srv.AuthorizationResponse(ctx, w, r, authReqID, authReq)
}
