package cryptutil

import (
	"crypto"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"

	"gopkg.in/square/go-jose.v2"
)

// PrivateJWKFromBytes returns a jose JSON Web _Private_ Key from bytes.
func PrivateJWKFromBytes(data []byte, alg jose.SignatureAlgorithm) (*jose.JSONWebKey, error) {
	return loadKey(data, alg, func(b []byte) (interface{}, error) {
		switch alg {
		case jose.ES256, jose.ES384, jose.ES512:
			return x509.ParseECPrivateKey(b)
		case jose.RS256, jose.RS384, jose.RS512:
			return x509.ParsePKCS1PrivateKey(b)
		default:
			return nil, errors.New("unsupported signature algorithm")
		}
	})
}

// PublicJWKFromBytes returns a jose JSON Web _Public_ Key from bytes.
func PublicJWKFromBytes(data []byte, alg jose.SignatureAlgorithm) (*jose.JSONWebKey, error) {
	return loadKey(data, alg, func(b []byte) (interface{}, error) {
		switch alg {
		case jose.ES256, jose.ES384, jose.ES512:
			key, err := x509.ParseECPrivateKey(b)
			if err != nil {
				return nil, err
			}
			return key.Public(), nil
		case jose.RS256, jose.RS384, jose.RS512:
			key, err := x509.ParsePKCS1PrivateKey(b)
			if err != nil {
				return nil, err
			}
			return key.Public(), nil
		default:
			return nil, errors.New("unsupported signature algorithm")
		}
	})
}

func loadKey(data []byte, alg jose.SignatureAlgorithm, unmarshal func([]byte) (interface{}, error)) (*jose.JSONWebKey, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("file contained no PEM encoded data")
	}
	priv, err := unmarshal(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("unmarshal key: %w", err)
	}
	key := &jose.JSONWebKey{Key: priv, Use: "sig", Algorithm: string(alg)}
	thumbprint, err := key.Thumbprint(crypto.SHA256)
	if err != nil {
		return nil, fmt.Errorf("computing thumbprint: %w", err)
	}
	key.KeyID = hex.EncodeToString(thumbprint)
	return key, nil
}
