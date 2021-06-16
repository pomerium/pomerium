package databroker

import (
	"crypto/tls"
	"fmt"
	"time"

	"github.com/pomerium/pomerium/pkg/cryptutil"
)

var (
	// DefaultDeletePermanentlyAfter is the default amount of time to wait before deleting
	// a record permanently.
	DefaultDeletePermanentlyAfter = time.Hour
	// DefaultStorageType is the default storage type that Server use
	DefaultStorageType = "memory"
	// DefaultGetAllPageSize is the default page size for GetAll calls.
	DefaultGetAllPageSize = 50
	// DefaultRegistryTTL is the default registry time to live.
	DefaultRegistryTTL = time.Minute
)

type serverConfig struct {
	deletePermanentlyAfter  time.Duration
	secret                  []byte
	storageType             string
	storageConnectionString string
	storageCAFile           string
	storageCertSkipVerify   bool
	storageCertificate      *tls.Certificate
	getAllPageSize          int
	registryTTL             time.Duration
}

func newServerConfig(options ...ServerOption) *serverConfig {
	cfg := new(serverConfig)
	WithDeletePermanentlyAfter(DefaultDeletePermanentlyAfter)(cfg)
	WithStorageType(DefaultStorageType)(cfg)
	WithGetAllPageSize(DefaultGetAllPageSize)(cfg)
	WithRegistryTTL(DefaultRegistryTTL)(cfg)
	for _, option := range options {
		option(cfg)
	}
	return cfg
}

// A ServerOption customizes the server.
type ServerOption func(*serverConfig) error

// WithDeletePermanentlyAfter sets the deletePermanentlyAfter duration.
// If a record is deleted via Delete, it will be permanently deleted after
// the given duration.
func WithDeletePermanentlyAfter(dur time.Duration) ServerOption {
	return func(cfg *serverConfig) error {
		cfg.deletePermanentlyAfter = dur
		return nil
	}
}

// WithGetAllPageSize sets the page size for GetAll calls.
func WithGetAllPageSize(pageSize int) ServerOption {
	return func(cfg *serverConfig) error {
		cfg.getAllPageSize = pageSize
		return nil
	}
}

// WithRegistryTTL sets the registry time to live in the config.
func WithRegistryTTL(ttl time.Duration) ServerOption {
	return func(cfg *serverConfig) error {
		cfg.registryTTL = ttl
		return nil
	}
}

// WithGetSharedKey sets the secret in the config.
func WithGetSharedKey(getSharedKey func() ([]byte, error)) ServerOption {
	return func(cfg *serverConfig) error {
		sharedKey, err := getSharedKey()
		if err != nil {
			return fmt.Errorf("shared key is required and must be %d bytes long: %w", cryptutil.DefaultKeySize, err)
		}
		cfg.secret = sharedKey
		return nil
	}
}

// WithStorageType sets the storage type.
func WithStorageType(typ string) ServerOption {
	return func(cfg *serverConfig) error {
		cfg.storageType = typ
		return nil
	}
}

// WithStorageConnectionString sets the DSN for storage.
func WithStorageConnectionString(connStr string) ServerOption {
	return func(cfg *serverConfig) error {
		cfg.storageConnectionString = connStr
		return nil
	}
}

// WithStorageCAFile sets the CA file in the config.
func WithStorageCAFile(filePath string) ServerOption {
	return func(cfg *serverConfig) error {
		cfg.storageCAFile = filePath
		return nil
	}
}

// WithStorageCertSkipVerify sets the storageCertSkipVerify in the config.
func WithStorageCertSkipVerify(storageCertSkipVerify bool) ServerOption {
	return func(cfg *serverConfig) error {
		cfg.storageCertSkipVerify = storageCertSkipVerify
		return nil
	}
}

// WithStorageCertificate sets the storageCertificate in the config.
func WithStorageCertificate(certificate *tls.Certificate) ServerOption {
	return func(cfg *serverConfig) error {
		cfg.storageCertificate = certificate
		return nil
	}
}
