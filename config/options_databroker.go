package config

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/pomerium/pomerium/internal/urlutil"
	"github.com/pomerium/pomerium/pkg/grpc/config"
)

// Errors
var (
	ErrInvalidDataBrokerServiceURL              = errors.New("config: bad databroker service url")
	ErrInvalidDataBrokerInternalServiceURL      = errors.New("config: bad databroker internal service url")
	ErrMissingDataBrokerStorageConnectionString = errors.New("config: missing databroker storage backend dsn")
	ErrUnknownDataBrokerStorageType             = errors.New("config: unknown databroker storage backend type")
)

// DataBrokerOptions are options related to the databroker.
type DataBrokerOptions struct {
	URLString                   string   `mapstructure:"databroker_service_url" yaml:"databroker_service_url,omitempty"`
	URLStrings                  []string `mapstructure:"databroker_service_urls" yaml:"databroker_service_urls,omitempty"`
	InternalURLString           string   `mapstructure:"databroker_internal_service_url" yaml:"databroker_internal_service_url,omitempty"`
	StorageType                 string   `mapstructure:"databroker_storage_type" yaml:"databroker_storage_type,omitempty"`
	StorageConnectionString     string   `mapstructure:"databroker_storage_connection_string" yaml:"databroker_storage_connection_string,omitempty"`
	StorageConnectionStringFile string   `mapstructure:"databroker_storage_connection_string_file" yaml:"databroker_storage_connection_string_file,omitempty"`
}

// GetStorageConnectionString gets the databroker storage connection string from either a file
// or the config option directly. If from a file spaces are trimmed off the ends.
func (o *DataBrokerOptions) GetStorageConnectionString() (string, error) {
	if o.StorageConnectionStringFile != "" {
		bs, err := os.ReadFile(o.StorageConnectionStringFile)
		return strings.TrimSpace(string(bs)), err
	}

	return o.StorageConnectionString, nil
}

// FromProto sets options from a config settings protobuf.
func (o *DataBrokerOptions) FromProto(src *config.Settings) {
	setSlice(&o.URLStrings, src.DatabrokerServiceUrls)
	set(&o.InternalURLString, src.DatabrokerInternalServiceUrl)
	set(&o.StorageType, src.DatabrokerStorageType)
	set(&o.StorageConnectionString, src.DatabrokerStorageConnectionString)
}

// ToProto updates a config settings protobuf with databroker options.
func (o *DataBrokerOptions) ToProto(dst *config.Settings) {
	dst.DatabrokerServiceUrls = o.URLStrings
	copySrcToOptionalDest(&dst.DatabrokerInternalServiceUrl, &o.InternalURLString)
	copySrcToOptionalDest(&dst.DatabrokerStorageType, &o.StorageType)
	copySrcToOptionalDest(&dst.DatabrokerStorageConnectionString, valueOrFromFileRaw(o.StorageConnectionString, o.StorageConnectionStringFile))
}

// Validate validates the databroker options.
func (o *DataBrokerOptions) Validate() error {
	switch o.StorageType {
	case StorageInMemoryName:
	case StoragePostgresName:
		if o.StorageConnectionString == "" && o.StorageConnectionStringFile == "" {
			return ErrMissingDataBrokerStorageConnectionString
		}
	default:
		return ErrUnknownDataBrokerStorageType
	}

	if o.URLString != "" {
		_, err := urlutil.ParseAndValidateURL(o.URLString)
		if err != nil {
			return fmt.Errorf("%w %s: %w", ErrInvalidDataBrokerServiceURL, o.URLString, err)
		}
	}
	if o.InternalURLString != "" {
		_, err := urlutil.ParseAndValidateURL(o.InternalURLString)
		if err != nil {
			return fmt.Errorf("%w %s: %w", ErrInvalidDataBrokerInternalServiceURL, o.InternalURLString, err)
		}
	}
	for _, str := range o.URLStrings {
		_, err := urlutil.ParseAndValidateURL(str)
		if err != nil {
			return fmt.Errorf("%w %s: %w", ErrInvalidDataBrokerServiceURL, str, err)
		}
	}

	return nil
}
