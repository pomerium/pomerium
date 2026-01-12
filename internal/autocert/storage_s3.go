package autocert

import (
	"bytes"
	"context"
	"errors"
	"io"
	"io/fs"
	"sort"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/caddyserver/certmagic"
)

type s3Storage struct {
	client *s3.Client
	bucket string
	prefix string

	Locker
}

func newS3Storage(client *s3.Client, bucket, prefix string) *s3Storage {
	s := &s3Storage{
		client: client,
		bucket: bucket,
		prefix: prefix,
	}
	s.Locker = NewLocker(s.Store, s.Load, s.Delete)
	return s
}

func (s *s3Storage) Store(ctx context.Context, key string, value []byte) error {
	_, err := s.client.PutObject(ctx, &s3.PutObjectInput{
		Bucket: aws.String(s.bucket),
		Key:    aws.String(s.prefix + key),
		Body:   bytes.NewReader(value),
	})
	return err
}

func (s *s3Storage) Load(ctx context.Context, key string) ([]byte, error) {
	output, err := s.client.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(s.bucket),
		Key:    aws.String(s.prefix + key),
	})

	var nsk *types.NoSuchKey
	if err != nil && errors.As(err, &nsk) {
		return nil, fs.ErrNotExist
	} else if err != nil {
		return nil, err
	}
	defer output.Body.Close()

	return io.ReadAll(output.Body)
}

func (s *s3Storage) Delete(ctx context.Context, key string) error {
	_, err := s.client.DeleteObject(ctx, &s3.DeleteObjectInput{
		Bucket: aws.String(s.bucket),
		Key:    aws.String(s.prefix + key),
	})
	return err
}

func (s *s3Storage) Exists(ctx context.Context, key string) bool {
	_, err := s.client.HeadObject(ctx, &s3.HeadObjectInput{
		Bucket: aws.String(s.bucket),
		Key:    aws.String(s.prefix + key),
	})
	return err == nil
}

func (s *s3Storage) List(ctx context.Context, prefix string, recursive bool) ([]string, error) {
	var delimiter *string
	if !recursive {
		delimiter = aws.String("/")
	}

	var keys []string
	paginator := s3.NewListObjectsV2Paginator(s.client, &s3.ListObjectsV2Input{
		Bucket:    aws.String(s.bucket),
		Prefix:    aws.String(s.prefix + prefix),
		Delimiter: delimiter,
	})
	for paginator.HasMorePages() {
		output, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, commonPrefix := range output.CommonPrefixes {
			keys = append(keys, (*commonPrefix.Prefix)[len(s.prefix):])
		}
		for _, object := range output.Contents {
			keys = append(keys, (*object.Key)[len(s.prefix):])
		}
	}
	sort.Strings(keys)
	return keys, nil
}

func (s *s3Storage) Stat(ctx context.Context, key string) (certmagic.KeyInfo, error) {
	output, err := s.client.HeadObject(ctx, &s3.HeadObjectInput{
		Bucket: aws.String(s.bucket),
		Key:    aws.String(s.prefix + key),
	})
	if err != nil {
		return certmagic.KeyInfo{}, err
	}

	var size int64
	if output.ContentLength != nil {
		size = *output.ContentLength
	}

	return certmagic.KeyInfo{
		Key:        key,
		Modified:   *output.LastModified,
		Size:       size,
		IsTerminal: true,
	}, nil
}
