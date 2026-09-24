package agentic

import (
	"crypto/cipher"
	"crypto/sha256"
	"fmt"
	"io"

	"golang.org/x/crypto/hkdf"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/pkg/cryptutil"
)

// NewCipher derives the AEAD cipher used to seal agentic run tokens. It shares
// the deployment shared key with MCP access tokens but uses a distinct HKDF
// info string, so a run token can never be decrypted as an MCP token (or vice
// versa) even though both start from the same secret.
func NewCipher(cfg *config.Config) (cipher.AEAD, error) {
	secret, err := cfg.Options.GetSharedKey()
	if err != nil {
		return nil, fmt.Errorf("shared key: %w", err)
	}

	rnd := hkdf.New(sha256.New, secret, nil, []byte("pomerium-agentic-run"))
	c, err := initCipher(rnd)
	if err != nil {
		return nil, fmt.Errorf("new aead cipher: %w", err)
	}
	return c, nil
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
	c, err := cryptutil.NewAEADCipher(cipherKey)
	if err != nil {
		return nil, fmt.Errorf("new aead cipher: %w", err)
	}
	return c, nil
}
