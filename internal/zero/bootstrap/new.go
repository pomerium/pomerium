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
	sdk "github.com/pomerium/pomerium/internal/zero/api"
	"github.com/pomerium/pomerium/internal/zero/bootstrap/writers"
	"github.com/pomerium/pomerium/pkg/cryptutil"
	"github.com/pomerium/pomerium/pkg/netutil"
)

// Source is a base config layer for Pomerium
type Source struct {
	source

	api *sdk.API

	fileCachePath *string
	fileCipher    cipher.AEAD
	writer        writers.ConfigWriter

	checkForUpdate chan struct{}
	updateInterval atomicutil.Value[time.Duration]
}

// New creates a new bootstrap config source
func New(secret []byte, fileCachePath *string, writer writers.ConfigWriter, api *sdk.API) (*Source, error) {
	cfg := new(config.Config)

	err := setConfigDefaults(cfg)
	if err != nil {
		return nil, fmt.Errorf("config defaults: %w", err)
	}

	rnd := hkdf.New(sha256.New, secret, nil, nil)

	err = initSecrets(cfg, rnd)
	if err != nil {
		return nil, fmt.Errorf("init secrets: %w", err)
	}

	cipher, err := initCipher(rnd)
	if err != nil {
		return nil, fmt.Errorf("init cypher: %w", err)
	}

	if writer != nil {
		writer = writer.WithOptions(writers.ConfigWriterOptions{
			Cipher: cipher,
		})
	}

	svc := &Source{
		api:            api,
		source:         source{ready: make(chan struct{})},
		fileCachePath:  fileCachePath,
		fileCipher:     cipher,
		checkForUpdate: make(chan struct{}, 1),
		writer:         writer,
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

	cookieSecret, err := readKey(r)
	if err != nil {
		return fmt.Errorf("read key: %w", err)
	}

	cfg.Options.CookieSecret = base64.StdEncoding.EncodeToString(cookieSecret)
	cfg.Options.SigningKey = base64.StdEncoding.EncodeToString(signingKeyEncoded)

	return nil
}
