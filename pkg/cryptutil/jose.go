package cryptutil

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"

	"github.com/go-jose/go-jose/v3"
	"github.com/hashicorp/go-multierror"
)

// PrivateJWKFromBytes returns a jose JSON Web _Private_ Key from bytes.
func PrivateJWKFromBytes(data []byte) (*jose.JSONWebKey, error) {
	jwks, err := loadKeys(data, loadPrivateKey)
	if err != nil {
		return nil, err
	} else if len(jwks) == 0 {
		return nil, fmt.Errorf("invalid pem data")
	}
	return jwks[0], nil
}

// PrivateJWKsFromBytes returns jose JSON Web _Private_ Keys from bytes.
func PrivateJWKsFromBytes(data []byte) ([]*jose.JSONWebKey, error) {
	return loadKeys(data, loadPrivateKey)
}

// PublicJWKFromBytes returns a jose JSON Web _Public_ Key from bytes.
func PublicJWKFromBytes(data []byte) (*jose.JSONWebKey, error) {
	jwks, err := loadKeys(data, loadPublicKey)
	if err != nil {
		return nil, err
	} else if len(jwks) == 0 {
		return nil, fmt.Errorf("invalid pem data")
	}
	return jwks[0], nil
}

// PublicJWKsFromBytes returns jose JSON Web _Public_ Keys from bytes.
func PublicJWKsFromBytes(data []byte) ([]*jose.JSONWebKey, error) {
	return loadKeys(data, loadPublicKey)
}

func loadKeys(data []byte, unmarshal func([]byte) (any, error)) ([]*jose.JSONWebKey, error) {
	var jwks []*jose.JSONWebKey
	for {
		var block *pem.Block
		block, data = pem.Decode(data)
		if block == nil {
			break
		}

		key, err := unmarshal(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("unmarshal key: %w", err)
		}

		alg, err := SignatureAlgorithmForKey(key)
		if err != nil {
			return nil, err
		}

		jwk := &jose.JSONWebKey{Key: key, Use: "sig", Algorithm: string(alg)}
		thumbprint, err := jwk.Thumbprint(crypto.SHA256)
		if err != nil {
			return nil, fmt.Errorf("computing thumbprint: %w", err)
		}
		jwk.KeyID = hex.EncodeToString(thumbprint)
		jwks = append(jwks, jwk)
	}
	return jwks, nil
}

func loadPrivateKey(b []byte) (any, error) {
	var wrappedErr error
	var err error
	var key any

	if key, err = x509.ParseECPrivateKey(b); err == nil {
		return key, nil
	}
	wrappedErr = multierror.Append(wrappedErr, err)

	if key, err = x509.ParsePKCS1PrivateKey(b); err == nil {
		return key, nil
	}
	wrappedErr = multierror.Append(wrappedErr, err)

	if key, err = x509.ParsePKCS8PrivateKey(b); err == nil {
		return key, nil
	}
	wrappedErr = multierror.Append(wrappedErr, err)

	return nil, fmt.Errorf("couldn't load private key: %w", wrappedErr)
}

// https://github.com/square/go-jose/tree/v2.5.1#supported-key-types
func loadPublicKey(b []byte) (any, error) {
	var wrappedErr error
	var err error
	var key any

	if key, err = loadPrivateKey(b); err == nil {
		switch k := key.(type) {
		case *rsa.PrivateKey:
			return k.Public(), nil
		case *ecdsa.PrivateKey:
			return k.Public(), nil
		default:
			return nil, fmt.Errorf("private key is unsupported type")
		}
	}
	wrappedErr = multierror.Append(wrappedErr, err)

	if key, err = x509.ParsePKIXPublicKey(b); err == nil {
		return key, nil
	}
	wrappedErr = multierror.Append(wrappedErr, err)

	if key, err = x509.ParseCertificate(b); err == nil {
		return key, nil
	}
	wrappedErr = multierror.Append(wrappedErr, err)

	return nil, fmt.Errorf("couldn't load public key: %w", wrappedErr)
}

// SignatureAlgorithmForKey returns the signature algorithm for the given key.
func SignatureAlgorithmForKey(key any) (jose.SignatureAlgorithm, error) {
	switch key.(type) {
	case *ecdsa.PrivateKey, *ecdsa.PublicKey:
		return jose.ES256, nil
	case *rsa.PrivateKey, *rsa.PublicKey:
		return jose.RS256, nil
	default:
		return "", fmt.Errorf("crypto: unsupported key type for signing: %T", key)
	}
}
