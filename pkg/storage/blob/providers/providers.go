// !! WIP: not final
package providers

import (
	"context"
	"fmt"
	"net/url"

	"gocloud.dev/blob"
)

// OpenBucket creates a *blob.Bucket from a blob storage URI
// (e.g. "s3://bucket", "gs://bucket", "azblob://container").
//
// For S3 URIs, credentials can be embedded as userinfo:
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
	case "s3":
		if u.User != nil {
			return openS3Bucket(ctx, u)
		}
	case "gs":
		return gcsIdentityOpener.OpenBucketURL(ctx, u)
	case "azblob":
		return azureIdentityOpener.OpenBucketURL(ctx, u)
	}
	return blob.OpenBucket(ctx, bucketURI)
}
