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
	DiagnosticKeyID     byte = 1
	DiagnosticPublicKey      = must(parsePublicKey(`
-----BEGIN PUBLIC KEY-----
MCowBQYDK2VuAyEAGsDUHu1FPwN89ShuurVINishPAJNlsHwfOqJbyq4BjQ=
-----END PUBLIC KEY-----
`))
	kem  = hpke.DHKEM(ecdh.X25519())
	kdf  = hpke.HKDFSHA256()
	aead = hpke.AES256GCM()
)

// Decrypt decrypts data previously encrypted with Encrypt.
func Decrypt(getPrivateKey func(keyID byte, kemID, kdfID, aeadID uint16) (hpke.PrivateKey, error), encapsulated []byte) ([]byte, error) {
	keyID, kemID, kdfID, aeadID, ciphertext := decapsulate(encapsulated)
	privateKey, err := getPrivateKey(keyID, kemID, kdfID, aeadID)
	if err != nil {
		return nil, fmt.Errorf("diagnostics: error retrieving private key for message: %w", err)
	}
	plaintext, err := hpke.Open(
		privateKey,
		kdf,
		aead,
		nil,
		ciphertext,
	)
	if err != nil {
		return nil, fmt.Errorf("diagnostics: error decrypting data with hpke: %w", err)
	}
	return plaintext, nil
}

// Encrypt encrypts data using HPKE.
func Encrypt(keyID byte, publicKey hpke.PublicKey, plaintext []byte) ([]byte, error) {
	ciphertext, err := hpke.Seal(
		publicKey,
		kdf,
		aead,
		nil,
		plaintext,
	)
	if err != nil {
		return nil, fmt.Errorf("diagnostics: error encrypting data with hpke: %w", err)
	}

	return encapsulate(keyID, ciphertext), nil
}

func parsePublicKey(publicKeyPEM string) (hpke.PublicKey, error) {
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
			ecdhPublicKey, ok := pub.(*ecdh.PublicKey)
			if !ok {
				return nil, fmt.Errorf("expected diagnostic public key to be an ecdh key, got %T", pub)
			}
			hpkePublicKey, err := hpke.NewDHKEMPublicKey(ecdhPublicKey)
			if err != nil {
				return nil, fmt.Errorf("error reading diagnostic public key: %w", err)
			}
			return hpkePublicKey, nil
		}
	}
	return nil, fmt.Errorf("diagnostic public key not found")
}

func decapsulate(data []byte) (version byte, kemID, kdfID, aeadID uint16, ciphertext []byte) {
	if len(data) < 7 {
		return 0, 0, 0, 0, nil
	}
	version = data[0]
	kemID = binary.BigEndian.Uint16(data[1:3])
	kdfID = binary.BigEndian.Uint16(data[3:5])
	aeadID = binary.BigEndian.Uint16(data[5:7])
	ciphertext = data[7:]
	return version, kemID, kdfID, aeadID, ciphertext
}

func encapsulate(keyID byte, ciphertext []byte) []byte {
	// this follows the header format described in https://www.rfc-editor.org/info/rfc9458/#section-4.1
	hdr := []byte{keyID}
	hdr = binary.BigEndian.AppendUint16(hdr, kem.ID())
	hdr = binary.BigEndian.AppendUint16(hdr, kdf.ID())
	hdr = binary.BigEndian.AppendUint16(hdr, aead.ID())
	return append(hdr, ciphertext...)
}

func must[T any](v T, err error) T {
	if err != nil {
		panic(err)
	}
	return v
}
