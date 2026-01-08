package autocert

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"cloud.google.com/go/storage"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/caddyserver/certmagic"
)

type Storage interface {
	certmagic.Storage
	certmagic.TryLocker
}

var (
	errUnknownStorageProvider = errors.New("unknown storage provider")
	s3virtualRE               = regexp.MustCompile(`^([-a-zA-Z0-9]+)\.s3\.([-a-zA-Z0-9]+)\.amazonaws\.com(/.*)?$`)
	s3hostRE                  = regexp.MustCompile(`^([^/]+)/([^/]+)(/.*)?$`)
	gcsRE                     = regexp.MustCompile(`^([^/]+)(/.*)?$`)
)

// GetCertMagicStorage gets the certmagic storage provider based on the destination.
func GetCertMagicStorage(ctx context.Context, dst string) (Storage, error) {
	idx := strings.Index(dst, "://")
	if idx == -1 {
		return &certmagic.FileStorage{Path: dst}, nil
	}

	scheme := dst[:idx]
	switch scheme {
	case "gs":
		bucket := ""
		prefix := ""

		if match := gcsRE.FindStringSubmatch(dst[idx+3:]); len(match) == 3 {
			bucket = match[1]
			prefix = strings.TrimPrefix(match[2], "/")
		} else {
			return nil, fmt.Errorf("autocert: invalid gcs storage location")
		}

		if prefix != "" && !strings.HasSuffix(prefix, "/") {
			prefix += "/"
		}

		client, err := storage.NewClient(ctx)
		if err != nil {
			return nil, fmt.Errorf("autocert: error creating gcs storage client: %w", err)
		}

		return newGCSStorage(client, bucket, prefix), nil

	case "s3":
		bucket := ""
		prefix := ""
		var options []func(*config.LoadOptions) error

		if match := s3virtualRE.FindStringSubmatch(dst[idx+3:]); len(match) == 4 {
			// s3://{bucket}.s3.{region}.amazonaws.com/{prefix}
			bucket = match[1]
			prefix = strings.TrimPrefix(match[3], "/")
			options = append(options, config.WithRegion(match[2]))
		} else if match := s3hostRE.FindStringSubmatch(dst[idx+3:]); len(match) == 4 {
			// s3://{host}/{bucket-name}/{prefix}
			host := match[1]
			if idx := strings.Index(host, "@"); idx >= 0 {
				username, password := host[:idx], ""
				host = host[idx+1:]

				if idx = strings.Index(username, ":"); idx >= 0 {
					username, password = username[:idx], username[idx+1:]
				}

				options = append(options, config.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(username, password, "")))
			}
			bucket = match[2]
			prefix = strings.TrimPrefix(match[3][1:], "/")
			options = append(options,
				config.WithRegion("us-east-1"),
				config.WithEndpointResolver(aws.EndpointResolverFunc(func(_, _ string) (aws.Endpoint, error) {
					return aws.Endpoint{
						PartitionID:       "aws",
						URL:               "http://" + host,
						SigningRegion:     "us-east-1",
						HostnameImmutable: true,
					}, nil
				})))
		} else {
			return nil, fmt.Errorf("autocert: invalid s3 storage location")
		}

		if prefix != "" && !strings.HasSuffix(prefix, "/") {
			prefix += "/"
		}

		cfg, err := config.LoadDefaultConfig(ctx, options...)
		if err != nil {
			return nil, fmt.Errorf("autocert: error creating aws config: %w", err)
		}

		client := s3.NewFromConfig(cfg)

		return newS3Storage(client, bucket, prefix), nil
	}

	return nil, errUnknownStorageProvider
}
