package blob

// S3Config holds S3-specific configuration, also used for S3-compatible
// providers like MinIO.
type S3Config struct {
	// Endpoint is the S3 API endpoint (e.g. "localhost:9000" for MinIO).
	Endpoint string `mapstructure:"endpoint" yaml:"endpoint,omitempty"`
	// AccessKey is the S3 access key ID.
	AccessKey string `mapstructure:"access_key" yaml:"access_key,omitempty"`
	// SecretKey is the S3 secret access key.
	SecretKey string `mapstructure:"secret_key" yaml:"secret_key,omitempty"`
	// Region is the S3 region (e.g. "us-east-1").
	Region string `mapstructure:"region" yaml:"region,omitempty"`
	// Insecure disables TLS for the S3 endpoint.
	Insecure bool `mapstructure:"insecure" yaml:"insecure,omitempty"`
}

// BlobStorageConfig holds the configuration for connecting to a blob storage provider.
type StorageConfig struct {
	// Provider is the blob storage provider type (e.g. "S3", "GCS", "AZURE").
	Provider string `mapstructure:"provider" yaml:"provider"`
	// Bucket is the bucket or container name.
	Bucket string `mapstructure:"bucket" yaml:"bucket"`
	// S3 holds S3-specific configuration. Only used when Provider is "S3".
	S3 *S3Config `mapstructure:"s3" yaml:"s3,omitempty"`
}
