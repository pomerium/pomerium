package mcp

import (
	"context"
	"fmt"
	"time"

	"github.com/pomerium/pomerium/internal/oauth21"
)

func CheckPKCE(
	codeChallengeMethod string,
	codeChallenge string,
	codeVerifier string,
) error {
	if codeChallengeMethod == "" || codeChallengeMethod == "plain" {
		if !oauth21.VerifyPKCEPlain(codeVerifier, codeChallenge) {
			return fmt.Errorf("plain: code verifier does not match code challenge")
		}
	} else if codeChallengeMethod == "S256" {
		if !oauth21.VerifyPKCES256(codeVerifier, codeChallenge) {
			return fmt.Errorf("S256: code verifier does not match code challenge")
		}
	} else {
		return fmt.Errorf("unsupported code challenge method: %s", codeChallengeMethod)
	}

	return nil
}

// GetAccessTokenForSession returns an access token for a given session and expiration time.
func (srv *Handler) GetAccessTokenForSession(sessionID string, sessionExpiresAt time.Time) (string, error) {
	return CreateCode(CodeTypeAccess, sessionID, sessionExpiresAt, "", srv.cipher)
}

// DecryptAuthorizationCode decrypts the authorization code and returns the underlying session ID
func (srv *Handler) GetSessionIDFromAccessToken(accessToken string) (string, error) {
	code, err := DecryptCode(CodeTypeAccess, accessToken, srv.cipher, "", time.Now())
	if err != nil {
		return "", err
	}

	return code.Id, nil
}

// GetUpstreamOAuth2Token retrieves the OAuth2 token for a given host and user ID.
// it also checks if the token is still valid and refreshes it if necessary.
func (srv *Handler) GetUpstreamOAuth2Token(
	ctx context.Context,
	host string,
	userID string,
) (string, error) {
	token, err, _ := srv.hostsSingleFlight.Do(host, func() (any, error) {
		tokenPB, err := srv.storage.GetUpstreamOAuth2Token(ctx, host, userID)
		if err != nil {
			return "", fmt.Errorf("failed to get upstream oauth2 token: %w", err)
		}

		cfg, ok := srv.hosts.GetOAuth2ConfigForHost(host)
		if !ok {
			return "", fmt.Errorf("no OAuth2 config found for host %s", host)
		}

		token, err := cfg.TokenSource(ctx, PBToOAuth2Token(tokenPB)).Token()
		if err != nil {
			return "", fmt.Errorf("failed to get OAuth2 token: %w", err)
		}
		if token.AccessToken != tokenPB.GetAccessToken() ||
			token.RefreshToken != tokenPB.GetRefreshToken() {
			err = srv.storage.StoreUpstreamOAuth2Token(ctx, host, userID, OAuth2TokenToPB(token))
			if err != nil {
				return "", fmt.Errorf("failed to store updated upstream oauth2 token: %w", err)
			}
		}

		return token.AccessToken, nil
	})
	if err != nil {
		return "", err
	}
	return token.(string), nil
}
