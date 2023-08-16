package bootstrap

import (
	"crypto/cipher"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"time"

	"golang.org/x/crypto/hkdf"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/atomicutil"
	"github.com/pomerium/pomerium/internal/deterministicecdsa"
	"github.com/pomerium/pomerium/pkg/cryptutil"
	"github.com/pomerium/pomerium/pkg/netutil"
	sdk "github.com/pomerium/zero-sdk"
)

// Source is a base config layer for Pomerium
type Source struct {
	source

	api *sdk.API

	fileCachePath string
	fileCipher    cipher.AEAD

	checkForUpdate chan struct{}
	updateInterval atomicutil.Value[time.Duration]
}

// New creates a new bootstrap config source
func New(secret []byte) (*Source, error) {
	cfg := new(config.Config)

	err := setConfigDefaults(cfg)
	if err != nil {
		return nil, fmt.Errorf("config defaults: %w", err)
	}

	rnd := hkdf.New(sha256.New, secret, nil, nil)

	cipher, err := initCipher(rnd)
	if err != nil {
		return nil, fmt.Errorf("init cypher: %w", err)
	}

	err = initSecrets(cfg, rnd)
	if err != nil {
		return nil, fmt.Errorf("init secrets: %w", err)
	}

	svc := &Source{
		source:         source{ready: make(chan struct{})},
		fileCipher:     cipher,
		checkForUpdate: make(chan struct{}, 1),
	}
	svc.cfg.Store(cfg)
	svc.updateInterval.Store(DefaultCheckForUpdateIntervalWhenDisconnected)

	return svc, nil
}

func setConfigDefaults(cfg *config.Config) error {
	cfg.Options = config.NewDefaultOptions()

	ports, err := netutil.AllocatePorts(6)
	if err != nil {
		return fmt.Errorf("allocating ports: %w", err)
	}

	cfg.AllocatePorts(*(*[6]string)(ports[:6]))

	return nil
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

func initSecrets(cfg *config.Config, r io.Reader) error {
	signingKey, err := deterministicecdsa.GenerateKey(elliptic.P256(), r)
	if err != nil {
		return fmt.Errorf("read key: %w", err)
	}
	signingKeyEncoded, err := cryptutil.EncodePrivateKey(signingKey)
	if err != nil {
		return fmt.Errorf("pem: %w", err)
	}

	sharedKey, err := readKey(r)
	if err != nil {
		return fmt.Errorf("read key: %w", err)
	}

	cookieSecret, err := readKey(r)
	if err != nil {
		return fmt.Errorf("read key: %w", err)
	}

	cfg.Options.SharedKey = base64.StdEncoding.EncodeToString(sharedKey)
	cfg.Options.CookieSecret = base64.StdEncoding.EncodeToString(cookieSecret)
	cfg.Options.SigningKey = base64.StdEncoding.EncodeToString(signingKeyEncoded)

	return nil
}
