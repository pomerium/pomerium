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
	return srv.GetAccessTokenForSessionWithVersion(sessionID, 0, sessionExpiresAt)
}

// GetAccessTokenForSessionWithVersion returns an access token that also carries
// the session's databroker record version, so the authorize service can read
// the session with a read-your-writes (minimum-version) guarantee.
func (srv *Handler) GetAccessTokenForSessionWithVersion(sessionID string, sessionRecordVersion uint64, sessionExpiresAt time.Time) (string, error) {
	return CreateCodeWithRecordVersion(CodeTypeAccess, sessionID, sessionExpiresAt, "", srv.cipher, sessionRecordVersion)
}

// CreateRefreshToken creates a refresh token for a given session and client.
func (srv *Handler) CreateRefreshToken(sessionID string, clientID string, expiresAt time.Time) (string, error) {
	return CreateCode(CodeTypeRefresh, sessionID, expiresAt, clientID, srv.cipher)
}

// DecryptRefreshToken decrypts and validates a refresh token.
func (srv *Handler) DecryptRefreshToken(refreshToken string, clientID string) (*oauth21proto.Code, error) {
	return DecryptCode(CodeTypeRefresh, refreshToken, srv.cipher, clientID, time.Now())
}

// GetSessionIDFromAccessToken decrypts the access token and returns the
// underlying session ID.
func (srv *Handler) GetSessionIDFromAccessToken(accessToken string) (string, error) {
	sessionID, _, err := srv.GetSessionAndVersionFromAccessToken(accessToken)
	return sessionID, err
}

// GetSessionAndVersionFromAccessToken decrypts the access token and returns the
// underlying session ID together with the databroker record version recorded at
// issuance time (zero if none).
func (srv *Handler) GetSessionAndVersionFromAccessToken(accessToken string) (string, uint64, error) {
	code, err := DecryptCode(CodeTypeAccess, accessToken, srv.cipher, "", time.Now())
	if err != nil {
		return "", 0, err
	}

	return code.Id, code.GetRecordVersion(), nil
}
