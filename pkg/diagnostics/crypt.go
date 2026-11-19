package diagnostics

import (
	"crypto/ecdh"
	"crypto/hpke"
	"crypto/x509"
	"encoding/binary"
	"encoding/pem"
	"fmt"
)

var (
	DiagnosticKeyID        byte = 1
	DiagnosticPublicKeyPEM      = `
-----BEGIN PUBLIC KEY-----
MCowBQYDK2VuAyEAGsDUHu1FPwN89ShuurVINishPAJNlsHwfOqJbyq4BjQ=
-----END PUBLIC KEY-----
`
)

// Decrypt decrypts data previously encrypted with Encrypt.
func Decrypt(privateKeyPEMs map[byte]string, encapsulated []byte) ([]byte, error) {
	keyID, ciphertext := decapsulate(encapsulated)
	privateKeyPEM, ok := privateKeyPEMs[keyID]
	if !ok {
		return nil, fmt.Errorf("diagnostics: data was encrypted with an unknown key")
	}
	key, err := getPrivateKey(privateKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("diagnostics: error loading private key: %w", err)
	}
	hpkeKey, err := hpke.NewDHKEMPrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("diagnostics: error loading private key: %w", err)
	}
	plaintext, err := hpke.Open(
		hpkeKey,
		hpke.HKDFSHA256(),
		hpke.ChaCha20Poly1305(),
		nil,
		ciphertext,
	)
	if err != nil {
		return nil, fmt.Errorf("diagnostics: error decrypting data with hpke: %w", err)
	}
	return plaintext, nil
}

// Encrypt encrypts data using HPKE.
func Encrypt(keyID byte, publicKeyPEM string, plaintext []byte) ([]byte, error) {
	key, err := getPublicKey(publicKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("diagnostics: error loading public key: %w", err)
	}
	hpkeKey, err := hpke.NewDHKEMPublicKey(key)
	if err != nil {
		return nil, fmt.Errorf("diagnostics: error loading public key: %w", err)
	}
	ciphertext, err := hpke.Seal(
		hpkeKey,
		hpke.HKDFSHA256(),
		hpke.ChaCha20Poly1305(),
		nil,
		plaintext,
	)
	if err != nil {
		return nil, fmt.Errorf("diagnostics: error encrypting data with hpke: %w", err)
	}

	return encapsulate(keyID, ciphertext), nil
}

func getPrivateKey(privateKeyPEM string) (*ecdh.PrivateKey, error) {
	data := []byte(privateKeyPEM)
	for {
		var block *pem.Block
		block, data = pem.Decode(data)
		if block == nil {
			break
		}

		if block.Type == "PRIVATE KEY" {
			priv, err := x509.ParsePKCS8PrivateKey(block.Bytes)
			if err != nil {
				return nil, fmt.Errorf("error parsing private key: %w", err)
			}
			key, ok := priv.(*ecdh.PrivateKey)
			if !ok {
				return nil, fmt.Errorf("expected private key to be an ecdh key, got %T", priv)
			}
			return key, nil
		}
	}
	return nil, fmt.Errorf("private key not found")
}

func getPublicKey(publicKeyPEM string) (*ecdh.PublicKey, error) {
	data := []byte(publicKeyPEM)
	for {
		var block *pem.Block
		block, data = pem.Decode(data)
		if block == nil {
			break
		}

		if block.Type == "PUBLIC KEY" {
			pub, err := x509.ParsePKIXPublicKey(block.Bytes)
			if err != nil {
				return nil, fmt.Errorf("error parsing diagnostic public key: %w", err)
			}
			key, ok := pub.(*ecdh.PublicKey)
			if !ok {
				return nil, fmt.Errorf("expected diagnostic public key to be an ecdh key, got %T", pub)
			}
			return key, nil
		}
	}
	return nil, fmt.Errorf("diagnostic public key not found")
}

func decapsulate(data []byte) (version byte, ciphertext []byte) {
	if len(data) < 7 {
		return 0, nil
	}
	return data[0], data[7:]
}

func encapsulate(keyID byte, ciphertext []byte) []byte {
	// this follows the header format described in https://www.rfc-editor.org/info/rfc9458/#section-4.1
	hdr := []byte{keyID}
	hdr = binary.BigEndian.AppendUint16(hdr, 0x0020) // DHKEM(X25519, HKDF-SHA256)
	hdr = binary.BigEndian.AppendUint16(hdr, 0x0001) // HKDF-SHA256
	hdr = binary.BigEndian.AppendUint16(hdr, 0x0003) // ChaCha20Poly1305
	return append(hdr, ciphertext...)
}
