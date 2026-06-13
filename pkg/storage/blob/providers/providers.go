// !! WIP: not final
package providers

import (
	"context"
	"fmt"
	"net/url"

	"gocloud.dev/blob"
	// registers azure blob
	"gocloud.dev/blob/azureblob"
	// registers file blob
	_ "gocloud.dev/blob/fileblob"
	// registers gcs blob
	_ "gocloud.dev/blob/gcsblob"
	// registers s3 blob
	_ "gocloud.dev/blob/s3blob"
)

type Provider struct {
	credentialLoaders []CredentialsLoader
}

func NewProvider(credentialLoaders []CredentialsLoader) Provider {
	return Provider{
		credentialLoaders: credentialLoaders,
	}
}

func (p Provider) OpenBucket(ctx context.Context, bucketURI string) (*blob.Bucket, error) {
	if bucketURI == "" {
		return nil, fmt.Errorf("blob storage bucket URI is not set")
	}

	u, err := url.Parse(bucketURI)
	if err != nil {
		return nil, fmt.Errorf("parse bucket URI: %w", err)
	}

	switch u.Scheme {
	case "file":
		q := u.Query()
		if !q.Has("no_tmp_dir") {
			q.Set("no_tmp_dir", "true")
			u.RawQuery = q.Encode()
			bucketURI = u.String()
		}
	case "azblob":
		// TODO :
	case "s3":
		// TODO :
	case "gs":
		bucketOpener := &gcsCredsWrapper{
			credentialLoaders: p.credentialLoaders,
		}
		return bucketOpener.OpenBucketURL(ctx, u)
	}
	return blob.OpenBucket(ctx, bucketURI)
}

// OpenBucket creates a *blob.Bucket from a blob storage URI
// wraps underlying blob.OpenBucket for setting custom defaults for Pomerium usage
func OpenBucket(ctx context.Context, bucketURI string) (*blob.Bucket, error) {
	if bucketURI == "" {
		return nil, fmt.Errorf("blob storage bucket URI is not set")
	}

	u, err := url.Parse(bucketURI)
	if err != nil {
		return nil, fmt.Errorf("parse bucket URI: %w", err)
	}

	switch u.Scheme {
	case "file":
		q := u.Query()
		if !q.Has("no_tmp_dir") {
			q.Set("no_tmp_dir", "true")
			u.RawQuery = q.Encode()
			bucketURI = u.String()
		}
	case azureblob.Scheme:
		return openAzureBucket(ctx, u)
	}
	return blob.OpenBucket(ctx, bucketURI)
}

func openAzureBucket(ctx context.Context, u *url.URL) (*blob.Bucket, error) {
	credInfoT := newCredInfoFromEnv()
	opener := &azureblob.URLOpener{
		MakeClient:        credInfoT.NewClient,
		ServiceURLOptions: *azureblob.NewDefaultServiceURLOptions(),
	}
	return opener.OpenBucketURL(ctx, u)
}
