package mcp

import (
	"crypto/cipher"
	"crypto/sha256"
	"fmt"
	"io"

	"golang.org/x/crypto/hkdf"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/pkg/cryptutil"
)

func getCipher(
	cfg *config.Config,
) (cipher.AEAD, error) {
	secret, err := cfg.Options.GetSharedKey()
	if err != nil {
		return nil, fmt.Errorf("shared key: %w", err)
	}

	rnd := hkdf.New(sha256.New, secret, nil, []byte("model-context-protocol"))
	cipher, err := initCipher(rnd)
	if err != nil {
		return nil, fmt.Errorf("new aead cipher: %w", err)
	}
	return cipher, nil
}

func readKey(r io.Reader) ([]byte, error) {
	b := make([]byte, cryptutil.DefaultKeySize)
	_, err := io.ReadFull(r, b)
	if err != nil {
		return nil, fmt.Errorf("read from hkdf: %w", err)
	}
	return b, nil
}

func initCipher(r io.Reader) (cipher.AEAD, error) {
	cipherKey, err := readKey(r)
	if err != nil {
		return nil, fmt.Errorf("read key: %w", err)
	}
	cipher, err := cryptutil.NewAEADCipher(cipherKey)
	if err != nil {
		return nil, fmt.Errorf("new aead cipher: %w", err)
	}
	return cipher, nil
}
