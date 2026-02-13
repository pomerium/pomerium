package recording

import (
	"fmt"
	"net/http"
	"strings"

	kitlog "github.com/go-kit/log"
	"github.com/rs/zerolog"
	"github.com/thanos-io/objstore"
	objclient "github.com/thanos-io/objstore/client"
	"github.com/thanos-io/objstore/providers/azure"
	"github.com/thanos-io/objstore/providers/gcs"
	"github.com/thanos-io/objstore/providers/s3"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/pkg/storage/blob"
)

// NewBucketFromConfig creates an objstore.Bucket from the pomerium config.
func NewBucketFromConfig(cfg *config.Config) (objstore.Bucket, error) {
	if cfg.Options.BlobStorage == nil {
		return nil, fmt.Errorf("blob storage config is not set")
	}

	provider := objstore.ObjProvider(strings.ToUpper(cfg.Options.BlobStorage.Provider))
	bucket := cfg.Options.BlobStorage.Bucket

	var providerConfig any
	switch provider {
	case objstore.S3:
		providerConfig = defaultS3Config(bucket, cfg.Options.BlobStorage.S3)
	case objstore.GCS:
		providerConfig = defaultGCSConfig(bucket)
	case objstore.AZURE:
		providerConfig = defaultAzureConfig(bucket)
	default:
		return nil, fmt.Errorf("unsupported blob storage provider: %s", provider)
	}

	bCfg := &objclient.BucketConfig{
		Type:   provider,
		Config: providerConfig,
	}

	logger := newKitLogger(log.Logger())
	return objclient.NewBucketFromConfig(logger, bCfg, "pomerium-core", func(rt http.RoundTripper) http.RoundTripper {
		return rt
	})
}

func defaultS3Config(bucket string, s3Cfg *blob.S3Config) s3.Config {
	cfg := s3.Config{
		Bucket:     bucket,
		AWSSDKAuth: true,
	}
	if s3Cfg != nil {
		cfg.Endpoint = s3Cfg.Endpoint
		cfg.AccessKey = s3Cfg.AccessKey
		cfg.SecretKey = s3Cfg.SecretKey
		cfg.Region = s3Cfg.Region
		cfg.Insecure = s3Cfg.Insecure
		if cfg.AccessKey != "" {
			cfg.AWSSDKAuth = false
		}
	}
	return cfg
}

func defaultGCSConfig(bucket string) gcs.Config {
	return gcs.Config{
		Bucket: bucket,
	}
}

func defaultAzureConfig(container string) azure.Config {
	return azure.Config{
		ContainerName: container,
	}
}

// kitLogger adapts a zerolog.Logger to the go-kit/log.Logger interface
// required by the thanos-io/objstore library.
type kitLogger struct {
	logger *zerolog.Logger
}

func newKitLogger(logger *zerolog.Logger) kitlog.Logger {
	return &kitLogger{logger: logger}
}

func (l *kitLogger) Log(keyvals ...any) error {
	e := l.logger.Info()

	for i := 0; i < len(keyvals)-1; i += 2 {
		key, ok := keyvals[i].(string)
		if !ok {
			key = fmt.Sprintf("%v", keyvals[i])
		}

		switch key {
		case "level":
			if level, ok := keyvals[i+1].(string); ok {
				switch level {
				case "debug":
					e = l.logger.Debug()
				case "warn":
					e = l.logger.Warn()
				case "error":
					e = l.logger.Error()
				default:
					e = l.logger.Info()
				}
				continue
			}
		case "msg":
			e.Msgf("%v", keyvals[i+1])
			return nil
		}

		e = e.Interface(key, keyvals[i+1])
	}

	e.Send()
	return nil
}
