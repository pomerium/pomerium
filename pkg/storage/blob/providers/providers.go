// !! WIP: not final
package providers

import (
	"context"
	"fmt"
	"net/url"

	"gocloud.dev/blob"
	// registers azure blob
	_ "gocloud.dev/blob/azureblob"
	// registers file blob
	_ "gocloud.dev/blob/fileblob"
	// registers gcs blob
	_ "gocloud.dev/blob/gcsblob"
	// registers s3 blob
	_ "gocloud.dev/blob/s3blob"
)

// OpenBucket creates a *blob.Bucket from a blob storage URI
// (e.g. "s3://bucket", "gs://bucket", "azblob://container").
//
// For minio S3 URIs, credentials can be embedded as userinfo:
//
//	s3://access_key:secret_key@bucket?region=us-east-1&endpoint=host:port&disable_https=true&use_path_style=true
func OpenBucket(ctx context.Context, bucketURI string) (*blob.Bucket, error) {
	if bucketURI == "" {
		return nil, fmt.Errorf("blob storage bucket URI is not set")
	}

	u, err := url.Parse(bucketURI)
	if err != nil {
		return nil, fmt.Errorf("parse bucket URI: %w", err)
	}

	switch u.Scheme {
	case "minio":
		if u.User != nil {
			return openMinioBucket(ctx, u)
		}
	}
	return blob.OpenBucket(ctx, bucketURI)
}
