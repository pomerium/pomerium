package mcp

import (
	"fmt"
	"strings"
	"time"

	"github.com/pomerium/pomerium/internal/oauth21"
	"github.com/pomerium/pomerium/internal/opaquetoken"
)

// Type prefixes for the opaque tokens this package mints. The '_' is disjoint
// from the standard-base64 token body, so trimming an absent prefix is
// unambiguous, and bare tokens issued before prefixing still parse.
const (
	accessTokenPrefix  = "pom_mat_"
	refreshTokenPrefix = "pom_mrt_"
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
func (srv *Handler) GetAccessTokenForSession(sessionID string, expiresAt time.Time) (string, error) {
	return srv.GetAccessTokenForSessionWithVersion(sessionID, 0, expiresAt)
}

// GetAccessTokenForSessionWithVersion returns an access token that also carries
// the session's databroker record version, so the authorize service can read
// the session with a read-your-writes (minimum-version) guarantee.
func (srv *Handler) GetAccessTokenForSessionWithVersion(sessionID string, sessionRecordVersion uint64, expiresAt time.Time) (string, error) {
	token, err := opaquetoken.Seal(opaquetoken.TypeAccess, sessionID, expiresAt, "", srv.cipher,
		opaquetoken.WithRecordVersion(sessionRecordVersion))
	if err != nil {
		return "", err
	}
	return accessTokenPrefix + token, nil
}

// CreateRefreshToken creates a refresh token for the MCP client session
// sessionID, bound to clientID. issuedAt is the session's issued_at at the time
// of minting: the token endpoint refuses a refresh token whose issued_at no
// longer matches the session's, which is how a rotated-away token is detected
// without a server-side record per token.
func (srv *Handler) CreateRefreshToken(sessionID string, clientID string, expiresAt, issuedAt time.Time) (string, error) {
	token, err := opaquetoken.Seal(opaquetoken.TypeRefresh, sessionID, expiresAt, clientID, srv.cipher,
		opaquetoken.WithIssuedAt(issuedAt))
	if err != nil {
		return "", err
	}
	return refreshTokenPrefix + token, nil
}

// DecryptRefreshToken decrypts and validates a refresh token.
func (srv *Handler) DecryptRefreshToken(refreshToken string, clientID string) (*opaquetoken.Payload, error) {
	return opaquetoken.Open(opaquetoken.TypeRefresh, strings.TrimPrefix(refreshToken, refreshTokenPrefix), srv.cipher, clientID, time.Now())
}

// GetSessionAndVersionFromAccessToken decrypts the access token and returns the
// underlying session ID together with the databroker record version recorded at
// issuance time (zero if none).
func (srv *Handler) GetSessionAndVersionFromAccessToken(accessToken string) (string, uint64, error) {
	payload, err := opaquetoken.Open(opaquetoken.TypeAccess, strings.TrimPrefix(accessToken, accessTokenPrefix), srv.cipher, "", time.Now())
	if err != nil {
		return "", 0, err
	}

	return payload.GetId(), payload.GetRecordVersion(), nil
}
