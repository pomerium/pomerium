// Package cryptutil provides encoding and decoding routines for various cryptographic structures.
package cryptutil // import "github.com/pomerium/pomerium/internal/cryptutil"

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
)

// DecodePublicKey decodes a PEM-encoded ECDSA public key.
func DecodePublicKey(encodedKey []byte) (*ecdsa.PublicKey, error) {
	block, _ := pem.Decode(encodedKey)
	if block == nil {
		return nil, fmt.Errorf("cryptutil: decoded nil PEM block")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	ecdsaPub, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		return nil, errors.New("cryptutil: data was not an ECDSA public key")
	}

	return ecdsaPub, nil
}

// EncodePublicKey encodes an ECDSA public key to PEM format.
func EncodePublicKey(key *ecdsa.PublicKey) ([]byte, error) {
	derBytes, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		return nil, err
	}

	block := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: derBytes,
	}

	return pem.EncodeToMemory(block), nil
}

// DecodePrivateKey decodes a PEM-encoded ECDSA private key.
func DecodePrivateKey(encodedKey []byte) (*ecdsa.PrivateKey, error) {
	var skippedTypes []string
	var block *pem.Block

	for {
		block, encodedKey = pem.Decode(encodedKey)

		if block == nil {
			return nil, fmt.Errorf("cryptutil: failed to find EC PRIVATE KEY in PEM data after skipping types %v", skippedTypes)
		}

		if block.Type == "EC PRIVATE KEY" {
			break
		} else {
			skippedTypes = append(skippedTypes, block.Type)
			continue
		}
	}

	privKey, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	return privKey, nil
}

// EncodePrivateKey encodes an ECDSA private key to PEM format.
func EncodePrivateKey(key *ecdsa.PrivateKey) ([]byte, error) {
	derKey, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, err
	}

	keyBlock := &pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: derKey,
	}

	return pem.EncodeToMemory(keyBlock), nil
}

// EncodeSignatureJWT encodes an ECDSA signature according to
// https://tools.ietf.org/html/rfc7515#appendix-A.3.1
func EncodeSignatureJWT(sig []byte) string {
	return base64.RawURLEncoding.EncodeToString(sig)
}

// DecodeSignatureJWT decodes an ECDSA signature according to
// https://tools.ietf.org/html/rfc7515#appendix-A.3.1
func DecodeSignatureJWT(b64sig string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(b64sig)
}
