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
	// 1. Calculate SHA256 hash of the code verifier (ASCII representation)
	sha256Hash := sha256.Sum256([]byte(codeVerifier))

	// 2. Base64url-encode the hash *without* padding
	//    Use RawURLEncoding which omits padding.
	calculatedChallenge := base64.RawURLEncoding.EncodeToString(sha256Hash[:])

	// 3. Constant-time comparison
	if len(calculatedChallenge) != len(storedCodeChallenge) {
		return false
	}
	// subtle.ConstantTimeCompare returns 1 if equal, 0 otherwise.
	return subtle.ConstantTimeCompare([]byte(calculatedChallenge), []byte(storedCodeChallenge)) == 1
}

// VerifyPKCEPlain verifies a PKCE challenge using the plain method.
// It performs a constant-time comparison to mitigate timing attacks.
//
// - codeVerifier: The verifier string sent by the client in the token request.
// - storedCodeChallenge: The challenge string stored by the server during the authorization request.
// Returns true if the verifier is valid, false otherwise.
func VerifyPKCEPlain(codeVerifier, storedCodeChallenge string) bool {
	if len(codeVerifier) != len(storedCodeChallenge) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(codeVerifier), []byte(storedCodeChallenge)) == 1
}
