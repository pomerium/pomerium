package mcp

import (
	"fmt"
	"time"

	"github.com/pomerium/pomerium/internal/oauth21"
	"github.com/pomerium/pomerium/internal/opaquetoken"
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
	return opaquetoken.Seal(opaquetoken.TypeAccess, sessionID, sessionExpiresAt, "", srv.cipher, sessionRecordVersion)
}

// CreateRefreshToken creates a refresh token for a given session and client.
func (srv *Handler) CreateRefreshToken(sessionID string, clientID string, expiresAt time.Time) (string, error) {
	return opaquetoken.Seal(opaquetoken.TypeRefresh, sessionID, expiresAt, clientID, srv.cipher, 0)
}

// DecryptRefreshToken decrypts and validates a refresh token.
func (srv *Handler) DecryptRefreshToken(refreshToken string, clientID string) (*opaquetoken.Payload, error) {
	return opaquetoken.Open(opaquetoken.TypeRefresh, refreshToken, srv.cipher, clientID, time.Now())
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
	payload, err := opaquetoken.Open(opaquetoken.TypeAccess, accessToken, srv.cipher, "", time.Now())
	if err != nil {
		return "", 0, err
	}

	return payload.GetId(), payload.GetRecordVersion(), nil
}
