package oauth21

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
)

// VerifyPKCES256 verifies a PKCE challenge using the S256 method.
// It performs a constant-time comparison to mitigate timing attacks.
//
// - codeVerifier: The verifier string sent by the client in the token request.
// - storedCodeChallenge: The challenge string stored by the server during the authorization request.
// Returns true if the verifier is valid, false otherwise.
func VerifyPKCES256(codeVerifier, storedCodeChallenge string) bool {
	sha256Hash := sha256.Sum256([]byte(codeVerifier))
	calculatedChallenge := base64.RawURLEncoding.EncodeToString(sha256Hash[:])
	return subtle.ConstantTimeCompare([]byte(calculatedChallenge), []byte(storedCodeChallenge)) == 1
}

// VerifyPKCEPlain verifies a PKCE challenge using the plain method.
// It performs a constant-time comparison to mitigate timing attacks.
//
// - codeVerifier: The verifier string sent by the client in the token request.
// - storedCodeChallenge: The challenge string stored by the server during the authorization request.
// Returns true if the verifier is valid, false otherwise.
func VerifyPKCEPlain(codeVerifier, storedCodeChallenge string) bool {
	return subtle.ConstantTimeCompare([]byte(codeVerifier), []byte(storedCodeChallenge)) == 1
}
