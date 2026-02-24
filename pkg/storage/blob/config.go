package blob

// BlobStorageConfig holds the configuration for connecting to a blob storage provider.
type StorageConfig struct {
	BucketURI     string `mapstructure:"bucket_uri"`
	ManagedPrefix string `mapstructure:"managed_prefix"`
}
