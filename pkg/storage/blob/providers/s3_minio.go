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

func openMinioBucket(ctx context.Context, u *url.URL) (*blob.Bucket, error) {
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
