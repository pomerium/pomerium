package databroker

import (
	"crypto/tls"
	"time"

	"github.com/pomerium/pomerium/internal/log"
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
type ServerOption func(*serverConfig)

// WithDeletePermanentlyAfter sets the deletePermanentlyAfter duration.
// If a record is deleted via Delete, it will be permanently deleted after
// the given duration.
func WithDeletePermanentlyAfter(dur time.Duration) ServerOption {
	return func(cfg *serverConfig) {
		cfg.deletePermanentlyAfter = dur
	}
}

// WithGetAllPageSize sets the page size for GetAll calls.
func WithGetAllPageSize(pageSize int) ServerOption {
	return func(cfg *serverConfig) {
		cfg.getAllPageSize = pageSize
	}
}

// WithRegistryTTL sets the registry time to live in the config.
func WithRegistryTTL(ttl time.Duration) ServerOption {
	return func(cfg *serverConfig) {
		cfg.registryTTL = ttl
	}
}

// WithGetSharedKey sets the secret in the config.
func WithGetSharedKey(getSharedKey func() ([]byte, error)) ServerOption {
	return func(cfg *serverConfig) {
		sharedKey, err := getSharedKey()
		if err != nil {
			log.Error().Err(err).Msgf("shared key is required and must be %d bytes long", cryptutil.DefaultKeySize)
			return
		}
		cfg.secret = sharedKey
	}
}

// WithStorageType sets the storage type.
func WithStorageType(typ string) ServerOption {
	return func(cfg *serverConfig) {
		cfg.storageType = typ
	}
}

// WithStorageConnectionString sets the DSN for storage.
func WithStorageConnectionString(connStr string) ServerOption {
	return func(cfg *serverConfig) {
		cfg.storageConnectionString = connStr
	}
}

// WithStorageCAFile sets the CA file in the config.
func WithStorageCAFile(filePath string) ServerOption {
	return func(cfg *serverConfig) {
		cfg.storageCAFile = filePath
	}
}

// WithStorageCertSkipVerify sets the storageCertSkipVerify in the config.
func WithStorageCertSkipVerify(storageCertSkipVerify bool) ServerOption {
	return func(cfg *serverConfig) {
		cfg.storageCertSkipVerify = storageCertSkipVerify
	}
}

// WithStorageCertificate sets the storageCertificate in the config.
func WithStorageCertificate(certificate *tls.Certificate) ServerOption {
	return func(cfg *serverConfig) {
		cfg.storageCertificate = certificate
	}
}
