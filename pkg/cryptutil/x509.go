package cryptutil

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"slices"
)

// https://tools.ietf.org/id/draft-ietf-curdle-pkix-05.html#rfc.section.3
var oidPublicKeyX25519 = asn1.ObjectIdentifier{1, 3, 101, 110}

// from x509, used for ASN.1
type (
	pkcs8 struct {
		Version    int
		Algo       pkix.AlgorithmIdentifier
		PrivateKey []byte
	}
	pkixPublicKey struct {
		Algo      pkix.AlgorithmIdentifier
		BitString asn1.BitString
	}
	publicKeyInfo struct {
		Raw       asn1.RawContent
		Algorithm pkix.AlgorithmIdentifier
		PublicKey asn1.BitString
	}
)

// MarshalPKCS8PrivateKey wraps x509.MarshalPKCS8PrivateKey with added support for KeyEncryptionKeys.
func MarshalPKCS8PrivateKey(key any) ([]byte, error) {
	// also support a pointer to a private key encryption key
	if kek, ok := key.(*PrivateKeyEncryptionKey); ok {
		key = *kek
	}
	if kek, ok := key.(PrivateKeyEncryptionKey); ok {
		var privKey pkcs8
		privKey.Algo = pkix.AlgorithmIdentifier{
			Algorithm: oidPublicKeyX25519,
		}
		curvePrivateKey, err := asn1.Marshal(kek.KeyBytes())
		if err != nil {
			return nil, fmt.Errorf("cryptutil: failed to marshal private key: %w", err)
		}
		privKey.PrivateKey = curvePrivateKey
		return asn1.Marshal(privKey)
	}

	// fall back to the original MarshalPKCS8PrivateKey
	return x509.MarshalPKCS8PrivateKey(key)
}

// MarshalPKIXPublicKey wraps x509.MarshalPKIXPublicKey with added support for KeyEncryptionKeys.
func MarshalPKIXPublicKey(pub any) ([]byte, error) {
	if kek, ok := pub.(*PublicKeyEncryptionKey); ok {
		pub = *kek
	}
	if kek, ok := pub.(PublicKeyEncryptionKey); ok {
		val := pkixPublicKey{
			Algo: pkix.AlgorithmIdentifier{
				Algorithm: oidPublicKeyX25519,
			},
			BitString: asn1.BitString{
				Bytes:     kek.KeyBytes(),
				BitLength: 8 * len(kek.KeyBytes()),
			},
		}
		ret, _ := asn1.Marshal(val)
		return ret, nil
	}

	// fall back to the original MarshalPKIXPublicKey
	return x509.MarshalPKIXPublicKey(pub)
}

// ParsePKCS8PrivateKey wraps x509.ParsePKCS8PrivateKey with added support for KeyEncryptionKeys.
func ParsePKCS8PrivateKey(der []byte) (any, error) {
	var privKey pkcs8
	_, err := asn1.Unmarshal(der, &privKey)
	if err != nil {
		return x509.ParsePKCS8PrivateKey(der)
	}

	if privKey.Algo.Algorithm.Equal(oidPublicKeyX25519) {
		var bs []byte
		if _, err := asn1.Unmarshal(privKey.PrivateKey, &bs); err != nil {
			return nil, fmt.Errorf("cryptutil: invalid X25519 private key: %w", err)
		}
		return NewPrivateKeyEncryptionKey(bs)
	}

	// fallback to the original ParsePKCS8PrivateKey
	return x509.ParsePKCS8PrivateKey(der)
}

// ParsePKIXPublicKey wraps x509.ParsePKIXPublicKey with added support for KeyEncryptionKeys.
func ParsePKIXPublicKey(derBytes []byte) (pub any, err error) {
	var pki publicKeyInfo
	rest, err := asn1.Unmarshal(derBytes, &pki)
	if err != nil || len(rest) > 0 {
		return x509.ParsePKIXPublicKey(derBytes)
	}

	if pki.Algorithm.Algorithm.Equal(oidPublicKeyX25519) {
		asn1Data := pki.PublicKey.RightAlign()
		// RFC 8410, Section 3
		// > For all of the OIDs, the parameters MUST be absent.
		if len(pki.Algorithm.Parameters.FullBytes) != 0 {
			return nil, errors.New("cryptutil: x25519 key encoded with illegal parameters")
		}
		if len(asn1Data) != KeyEncryptionKeySize {
			return nil, errors.New("cryptutil: wrong x25519 public key size")
		}
		pub := make([]byte, KeyEncryptionKeySize)
		copy(pub, asn1Data)
		return NewPublicKeyEncryptionKey(pub)
	}

	// fall back to the original ParsePKIXPublicKey
	return x509.ParsePKIXPublicKey(derBytes)
}

func FormatDistinguishedName(raw []byte) (string, error) {
	var rdns pkix.RDNSequence
	rest, err := asn1.Unmarshal(raw, &rdns)
	if err != nil {
		return "", fmt.Errorf("couldn't parse Distinguished Name: %w", err)
	} else if len(rest) > 0 {
		return "", fmt.Errorf("unexpected data after name")
	}

	// The output of RDNSequence.String() is reversed relative to the input.
	slices.Reverse(rdns)
	return rdns.String(), nil
}
