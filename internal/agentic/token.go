package agentic

import (
	"crypto/cipher"
	"strings"
	"time"

	"github.com/pomerium/pomerium/internal/opaquetoken"
)

// RunTokenPrefix marks an opaque agentic run token. It keeps run tokens disjoint
// from external-issuer JWTs (which never start with this prefix) so the
// authorize layer can dispatch on it cheaply.
const RunTokenPrefix = "pom_art_"

// MintRunToken seals an opaque run token referencing runID. sessionRecordVersion
// is embedded so the authorize-side session read can replay it as a
// read-your-writes minimum-version hint. expires must be non-zero.
func MintRunToken(c cipher.AEAD, runID string, expires time.Time, sessionRecordVersion uint64) (string, error) {
	code, err := opaquetoken.Seal(opaquetoken.TypeAccess, runID, expires, "", c,
		opaquetoken.WithRecordVersion(sessionRecordVersion))
	if err != nil {
		return "", err
	}
	return RunTokenPrefix + code, nil
}

// RunTokenFromAuthorizationHeader extracts a "Bearer pom_art_..." token from an
// Authorization header value. ok is false for any other value.
func RunTokenFromAuthorizationHeader(auth string) (string, bool) {
	const bearer = "Bearer "
	if len(auth) < len(bearer) || !strings.EqualFold(auth[:len(bearer)], bearer) {
		return "", false
	}
	tok := auth[len(bearer):]
	if !strings.HasPrefix(tok, RunTokenPrefix) {
		return "", false
	}
	return tok, true
}

// ParseRunToken decrypts a run token and returns the run id plus the embedded
// session record version. mcp.DecryptCode rejects expired codes and codes that
// are not access codes.
func ParseRunToken(c cipher.AEAD, token string) (runID string, sessionRecordVersion uint64, err error) {
	code, err := opaquetoken.Open(opaquetoken.TypeAccess, strings.TrimPrefix(token, RunTokenPrefix), c, "", time.Now())
	if err != nil {
		return "", 0, err
	}
	return code.GetId(), code.GetRecordVersion(), nil
}
