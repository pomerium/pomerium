package cryptutil

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
)

// NewSigningKey generates a random P-256 ECDSA private key.
// Go's P-256 is constant-time (which prevents certain types of attacks)
// while its P-384 and P-521 are not.
func NewSigningKey() (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
}
