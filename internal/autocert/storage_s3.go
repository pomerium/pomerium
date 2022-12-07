package autocert

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"sort"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/caddyserver/certmagic"
	"github.com/google/uuid"
)

const (
	s3lockDuration     = time.Second * 30
	s3lockPollInterval = time.Second
)

type s3lock struct {
	ID      string
	Expires time.Time
}

type s3Storage struct {
	client *s3.Client
	bucket string
	prefix string
}

func (s *s3Storage) Lock(ctx context.Context, name string) error {
	lockID := uuid.NewString()

	for {
		lock, err := s.getLock(ctx, name)
		if err != nil {
			return err
		}

		if lock != nil {
			if lock.ID == lockID {
				return nil
			} else if lock.Expires.Before(time.Now()) {
				// ignore the existing lock and take it ourselves
			} else {
				// wait
				select {
				case <-ctx.Done():
					return ctx.Err()
				case <-time.After(s3lockPollInterval):
				}
				continue
			}
		}

		// take the lock
		lock = &s3lock{ID: lockID, Expires: time.Now().Add(s3lockDuration)}
		err = s.putLock(ctx, name, lock)
		if err != nil {
			return err
		}
	}
}

func (s *s3Storage) Unlock(ctx context.Context, name string) error {
	return s.deleteLock(ctx, name)
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

	return certmagic.KeyInfo{
		Key:        key,
		Modified:   *output.LastModified,
		Size:       output.ContentLength,
		IsTerminal: true,
	}, nil
}

func (s *s3Storage) getLock(ctx context.Context, name string) (*s3lock, error) {
	key := fmt.Sprintf("locks/%s", name)

	output, err := s.client.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(s.bucket),
		Key:    aws.String(key),
	})
	var nsk *types.NoSuchKey
	if err != nil && errors.As(err, &nsk) {
		return nil, nil
	} else if err != nil {
		return nil, err
	}
	defer output.Body.Close()

	var lock s3lock
	err = json.NewDecoder(output.Body).Decode(&lock)
	if err != nil {
		return nil, err
	}

	return &lock, nil
}

func (s *s3Storage) putLock(ctx context.Context, name string, lock *s3lock) error {
	key := fmt.Sprintf("locks/%s", name)

	bs, err := json.Marshal(lock)
	if err != nil {
		return err
	}
	_, err = s.client.PutObject(ctx, &s3.PutObjectInput{
		Bucket: aws.String(s.bucket),
		Key:    aws.String(key),
		Body:   bytes.NewReader(bs),
	})
	return err
}

func (s *s3Storage) deleteLock(ctx context.Context, name string) error {
	key := fmt.Sprintf("locks/%s", name)

	_, err := s.client.DeleteObject(ctx, &s3.DeleteObjectInput{
		Bucket: aws.String(s.bucket),
		Key:    aws.String(key),
	})
	return err
}
