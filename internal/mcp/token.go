package mcp

import (
	"fmt"
	"time"

	"github.com/pomerium/pomerium/internal/oauth21"
	oauth21proto "github.com/pomerium/pomerium/internal/oauth21/gen"
)

func CheckPKCE(
	codeChallengeMethod string,
	codeChallenge string,
	codeVerifier string,
) error {
	switch codeChallengeMethod {
	case "", "plain":
		if !oauth21.VerifyPKCEPlain(codeVerifier, codeChallenge) {
			return fmt.Errorf("plain: code verifier does not match code challenge")
		}
	case "S256":
		if !oauth21.VerifyPKCES256(codeVerifier, codeChallenge) {
			return fmt.Errorf("S256: code verifier does not match code challenge")
		}
	default:
		return fmt.Errorf("unsupported code challenge method: %s", codeChallengeMethod)
	}

	return nil
}

// GetAccessTokenForSession returns an access token for a given session and expiration time.
func (srv *Handler) GetAccessTokenForSession(sessionID string, sessionExpiresAt time.Time) (string, error) {
	return CreateCode(CodeTypeAccess, sessionID, sessionExpiresAt, "", srv.cipher)
}

// CreateRefreshToken creates a refresh token for a given session and client.
func (srv *Handler) CreateRefreshToken(sessionID string, clientID string, expiresAt time.Time) (string, error) {
	return CreateCode(CodeTypeRefresh, sessionID, expiresAt, clientID, srv.cipher)
}

// DecryptRefreshToken decrypts and validates a refresh token.
func (srv *Handler) DecryptRefreshToken(refreshToken string, clientID string) (*oauth21proto.Code, error) {
	return DecryptCode(CodeTypeRefresh, refreshToken, srv.cipher, clientID, time.Now())
}

// DecryptAuthorizationCode decrypts the authorization code and returns the underlying session ID
func (srv *Handler) GetSessionIDFromAccessToken(accessToken string) (string, error) {
	code, err := DecryptCode(CodeTypeAccess, accessToken, srv.cipher, "", time.Now())
	if err != nil {
		return "", err
	}

	return code.Id, nil
}
