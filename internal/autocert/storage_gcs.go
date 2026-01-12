package autocert

import (
	"context"
	"errors"
	"io"
	"io/fs"

	"cloud.google.com/go/storage"
	"github.com/caddyserver/certmagic"
	"google.golang.org/api/iterator"
)

type gcsStorage struct {
	client *storage.Client
	bucket string
	prefix string

	Locker
}

func newGCSStorage(client *storage.Client, bucket, prefix string) *gcsStorage {
	s := &gcsStorage{
		client: client,
		bucket: bucket,
		prefix: prefix,
	}
	s.Locker = NewLocker(s.Store, s.Load, s.Delete)
	return s
}

func (s *gcsStorage) Store(ctx context.Context, key string, value []byte) error {
	obj := s.client.
		Bucket(s.bucket).
		Object(key)

	w := obj.NewWriter(ctx)
	_, err := w.Write(value)
	if err != nil {
		_ = w.CloseWithError(err)
		return err
	}

	err = w.Close()
	if err != nil {
		return err
	}

	return nil
}

func (s *gcsStorage) Load(ctx context.Context, key string) ([]byte, error) {
	r, err := s.client.
		Bucket(s.bucket).
		Object(key).
		NewReader(ctx)
	if errors.Is(err, storage.ErrObjectNotExist) {
		return nil, fs.ErrNotExist
	} else if err != nil {
		return nil, err
	}
	defer r.Close()

	return io.ReadAll(r)
}

func (s *gcsStorage) Delete(ctx context.Context, key string) error {
	err := s.client.
		Bucket(s.bucket).
		Object(key).
		Delete(ctx)
	if errors.Is(err, storage.ErrObjectNotExist) {
		return nil
	}
	return err
}

func (s *gcsStorage) Exists(ctx context.Context, key string) bool {
	_, err := s.client.
		Bucket(s.bucket).
		Object(key).
		Attrs(ctx)
	return err == nil
}

func (s *gcsStorage) List(ctx context.Context, prefix string, recursive bool) ([]string, error) {
	var delimiter string
	if !recursive {
		delimiter = "/"
	}

	it := s.client.
		Bucket(s.bucket).
		Objects(ctx, &storage.Query{
			Delimiter: delimiter,
			Prefix:    prefix,
		})
	var keys []string
	for {
		attrs, err := it.Next()
		if errors.Is(err, iterator.Done) {
			break
		} else if err != nil {
			return nil, err
		}

		if attrs.Prefix != "" {
			keys = append(keys, attrs.Prefix)
		} else {
			keys = append(keys, attrs.Name)
		}
	}
	return keys, nil
}

func (s *gcsStorage) Stat(ctx context.Context, key string) (certmagic.KeyInfo, error) {
	attrs, err := s.client.
		Bucket(s.bucket).
		Object(key).
		Attrs(ctx)
	if errors.Is(err, storage.ErrObjectNotExist) {
		return certmagic.KeyInfo{}, fs.ErrNotExist
	} else if err != nil {
		return certmagic.KeyInfo{}, err
	}

	return certmagic.KeyInfo{
		Key:        key,
		Modified:   attrs.Updated,
		Size:       attrs.Size,
		IsTerminal: true,
	}, nil
}
