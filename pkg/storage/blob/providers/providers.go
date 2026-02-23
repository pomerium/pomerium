// !! WIP: not final
package providers

import (
	"context"
	"fmt"
	"net/url"
	"strconv"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	awss3 "github.com/aws/aws-sdk-go-v2/service/s3"
	"gocloud.dev/blob"
	"gocloud.dev/blob/s3blob"
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

	if u.Scheme == "s3" && u.User != nil {
		return openS3Bucket(ctx, u)
	}

	return blob.OpenBucket(ctx, bucketURI)
}

func openS3Bucket(ctx context.Context, u *url.URL) (*blob.Bucket, error) {
	accessKey := u.User.Username()
	secretKey, _ := u.User.Password()
	bucket := u.Host

	q := u.Query()

	opts := []func(*awsconfig.LoadOptions) error{
		awsconfig.WithCredentialsProvider(
			credentials.NewStaticCredentialsProvider(accessKey, secretKey, ""),
		),
	}
	if region := q.Get("region"); region != "" {
		opts = append(opts, awsconfig.WithRegion(region))
	}

	cfg, err := awsconfig.LoadDefaultConfig(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("load AWS config: %w", err)
	}

	var s3Opts []func(*awss3.Options)
	if endpoint := q.Get("endpoint"); endpoint != "" {
		scheme := "https"
		if v, _ := strconv.ParseBool(q.Get("disable_https")); v {
			scheme = "http"
		}
		s3Opts = append(s3Opts, func(o *awss3.Options) {
			o.BaseEndpoint = aws.String(fmt.Sprintf("%s://%s", scheme, endpoint))
		})
	}
	if v, _ := strconv.ParseBool(q.Get("use_path_style")); v {
		s3Opts = append(s3Opts, func(o *awss3.Options) {
			o.UsePathStyle = true
		})
	}

	client := awss3.NewFromConfig(cfg, s3Opts...)
	return s3blob.OpenBucketV2(ctx, client, bucket, nil)
}
