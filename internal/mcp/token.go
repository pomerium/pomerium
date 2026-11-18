package mcp

import (
	"crypto/cipher"
	"fmt"
	"strings"
	"time"

	"github.com/pomerium/pomerium/config"
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

// AccessTokens seals and opens the MCP access tokens that the Handler issues.
// The authorize service uses it to read them without a Handler.
type AccessTokens struct {
	cipher cipher.AEAD
}

// NewAccessTokens creates AccessTokens keyed by the shared secret of cfg.
func NewAccessTokens(cfg *config.Config) (*AccessTokens, error) {
	c, err := getCipher(cfg)
	if err != nil {
		return nil, fmt.Errorf("get cipher: %w", err)
	}
	return &AccessTokens{cipher: c}, nil
}

// GetAccessTokenForSession returns an access token for a given session and expiration time.
func (t AccessTokens) GetAccessTokenForSession(sessionID string, sessionExpiresAt time.Time) (string, error) {
	return t.GetAccessTokenForSessionWithVersion(sessionID, 0, sessionExpiresAt)
}

// GetAccessTokenForSessionWithVersion returns an access token that also carries
// the session's databroker record version, so the authorize service can read
// the session with a read-your-writes (minimum-version) guarantee.
func (t AccessTokens) GetAccessTokenForSessionWithVersion(sessionID string, sessionRecordVersion uint64, sessionExpiresAt time.Time) (string, error) {
	token, err := opaquetoken.Seal(opaquetoken.TypeAccess, sessionID, sessionExpiresAt, "", t.cipher, sessionRecordVersion)
	if err != nil {
		return "", err
	}
	return accessTokenPrefix + token, nil
}

// GetSessionAndVersionFromAccessToken decrypts the access token and returns the
// underlying session ID together with the databroker record version recorded at
// issuance time (zero if none).
func (t AccessTokens) GetSessionAndVersionFromAccessToken(accessToken string) (string, uint64, error) {
	payload, err := opaquetoken.Open(opaquetoken.TypeAccess, strings.TrimPrefix(accessToken, accessTokenPrefix), t.cipher, "", time.Now())
	if err != nil {
		return "", 0, err
	}

	return payload.GetId(), payload.GetRecordVersion(), nil
}

// GetAccessTokenForSessionWithVersion is
// AccessTokens.GetAccessTokenForSessionWithVersion with the Handler's cipher.
func (srv *Handler) GetAccessTokenForSessionWithVersion(sessionID string, sessionRecordVersion uint64, sessionExpiresAt time.Time) (string, error) {
	return AccessTokens{cipher: srv.cipher}.GetAccessTokenForSessionWithVersion(sessionID, sessionRecordVersion, sessionExpiresAt)
}

// CreateRefreshToken creates a refresh token for a given session and client.
func (srv *Handler) CreateRefreshToken(sessionID string, clientID string, expiresAt time.Time) (string, error) {
	token, err := opaquetoken.Seal(opaquetoken.TypeRefresh, sessionID, expiresAt, clientID, srv.cipher, 0)
	if err != nil {
		return "", err
	}
	return refreshTokenPrefix + token, nil
}

// DecryptRefreshToken decrypts and validates a refresh token.
func (srv *Handler) DecryptRefreshToken(refreshToken string, clientID string) (*opaquetoken.Payload, error) {
	return opaquetoken.Open(opaquetoken.TypeRefresh, strings.TrimPrefix(refreshToken, refreshTokenPrefix), srv.cipher, clientID, time.Now())
}

// GetSessionIDFromAccessToken decrypts the access token and returns the
// underlying session ID.
func (srv *Handler) GetSessionIDFromAccessToken(accessToken string) (string, error) {
	sessionID, _, err := srv.GetSessionAndVersionFromAccessToken(accessToken)
	return sessionID, err
}

// GetSessionAndVersionFromAccessToken is
// AccessTokens.GetSessionAndVersionFromAccessToken with the Handler's cipher.
func (srv *Handler) GetSessionAndVersionFromAccessToken(accessToken string) (string, uint64, error) {
	return AccessTokens{cipher: srv.cipher}.GetSessionAndVersionFromAccessToken(accessToken)
}
