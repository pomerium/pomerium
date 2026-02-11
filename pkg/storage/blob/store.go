package blob

import (
	"context"
	"fmt"
	"io"
	"path"
	"reflect"
	"slices"
	"strings"
	"sync"

	"github.com/rs/zerolog"
	"github.com/thanos-io/objstore"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/log"
)

type Options struct {
	includeInstallationID bool
	// inMem is a testing only option
	inMem bool
}

func (o *Options) Apply(opts ...Option) {
	for _, opt := range opts {
		opt(o)
	}
}

func defaultOptions() *Options {
	return &Options{
		includeInstallationID: false,
		inMem:                 false,
	}
}

type Option func(o *Options)

func WithIncludeInstallationID() Option {
	return func(o *Options) {
		o.includeInstallationID = true
	}
}

const noInstallationID = "__global"

type Store[T any, TMsg interface {
	*T
	proto.Message
}] struct {
	ctx             context.Context
	mu              sync.RWMutex
	installationUID string
	prefix          string
	*Options

	bucket    objstore.Bucket
	bucketErr error
}

func NewStore[T any, TMsg interface {
	*T
	proto.Message
}](
	ctx context.Context,
	prefix string,
	opts ...Option,
) *Store[T, TMsg] {
	options := defaultOptions()

	options.Apply(opts...)
	b := &Store[T, TMsg]{
		ctx:     ctx,
		prefix:  prefix,
		Options: options,
	}
	return b
}

func (b *Store[T, TMsg]) Stop() {
	b.mu.Lock()
	b.closeBucketLocked()
	b.mu.Unlock()
}

func (b *Store[T, TMsg]) closeBucketLocked() {
	if b.bucket == nil {
		return
	}
	if err := b.bucket.Close(); err != nil {
		b.logger(b.ctx).Err(err).Msg("failed to close blob store bucket")
	}
}

func (b *Store[T, TMsg]) Querier() ObjectQuerier[T, TMsg] {
	return b
}

func (b *Store[T, TMsg]) Writer() ObjectWriter {
	return b
}

func (b *Store[T, TMsg]) Reader() ObjectReader {
	return b
}

func (b *Store[T, TMsg]) ReaderWriter() ObjectReaderWriter {
	return b
}

func (b *Store[T, TMsg]) logger(ctx context.Context) *zerolog.Logger {
	l := log.Ctx(ctx).With().
		Str("component", "Store").
		Str("blob-provider", b.provider()).
		Logger()
	return &l
}

func (b *Store[T, TMsg]) provider() string {
	if b.bucket == nil {
		return "none"
	}
	return strings.ToLower(string(b.bucket.Provider()))
}

func (b *Store[T, TMsg]) loggerForKey(ctx context.Context, key string) *zerolog.Logger {
	l := log.Ctx(ctx).With().
		Str("component", "Store").
		Str("blob-provider", b.provider()).
		Str("key", key).
		Logger()
	return &l
}

func (b *Store[T, TMsg]) objectPrefix() string {
	if b.includeInstallationID {
		return path.Join(b.prefix, b.installationUID)
	}
	return path.Join(b.prefix, noInstallationID)
}

func (b *Store[T, TMsg]) OnConfigChange(ctx context.Context, cfg *config.Config) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.installationUID != cfg.Options.InstallationID {
		b.logger(ctx).
			Warn().Str("incoming", cfg.Options.InstallationID).
			Str("previous", b.installationUID).
			Msg("installation id has changed")
	}
	b.installationUID = cfg.Options.InstallationID

	defer func() {
		if b.bucketErr != nil {
			log.Ctx(ctx).Err(b.bucketErr).Msg("error loading bucket from configuration")
		}
	}()

	bucket, err := b.bucketConfigFromOptions(ctx, cfg)
	if err != nil {
		b.bucketErr = fmt.Errorf("failed to construct bucket : %w", err)
		return
	}
	b.bucket = bucket
	if !slices.Contains(b.bucket.SupportedIterOptions(), objstore.Recursive) {
		b.bucketErr = fmt.Errorf("remote blob store must suppored recursive iteration")
		return
	}
	b.bucketErr = nil
}

func (b *Store[T, Tmsg]) bucketConfigFromOptions(_ context.Context, _ *config.Config) (objstore.Bucket, error) {
	if b.Options.inMem {
		return objstore.NewInMemBucket(), nil
	}
	panic("not implemented")
}

func (b *Store[T, TMsg]) objectPath(key string) string {
	return path.Join(b.objectPrefix(), key)
}

func (b *Store[T, TMsg]) metadataPath(key string) string {
	return path.Join(b.objectPrefix(), key+".attrs")
}

func (b *Store[T, TMsg]) getBucket() (objstore.Bucket, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()
	if b.bucketErr != nil {
		return nil, status.Error(codes.Internal, b.bucketErr.Error())
	}
	if b.bucket == nil {
		return nil, status.Error(codes.Unavailable, "blob storage not yet initialized")
	}
	return b.bucket, nil
}

func (b *Store[T, TMsg]) Put(ctx context.Context,
	key string,
	metadata io.Reader,
	contents io.Reader,
) error {
	bucket, err := b.getBucket()
	if err != nil {
		return err
	}

	objKey := b.objectPath(key)
	mdKey := b.metadataPath(key)
	if err := bucket.Upload(ctx, b.objectPath(key), contents); err != nil {
		b.loggerForKey(ctx, objKey).Err(err).Msg("failed to upload contents")
		return err
	}
	if err := bucket.Upload(ctx, b.metadataPath(key), metadata); err != nil {
		b.loggerForKey(ctx, mdKey).Err(err).Str("key", key).Msg("failed to upload metadata")
		return err
	}
	return nil
}

func (b *Store[T, TMsg]) get(ctx context.Context, fullKey string) ([]byte, error) {
	logger := b.loggerForKey(ctx, fullKey)
	bucket, err := b.getBucket()
	if err != nil {
		return nil, err
	}
	rc, err := bucket.Get(ctx, fullKey)
	if err != nil {
		logger.Err(err).Msg("failed to read metadata")
		return nil, err
	}
	data, readErr := io.ReadAll(rc)
	if closeErr := rc.Close(); closeErr != nil {
		logger.Err(closeErr).Msg("failed to close metadata reader")
	}
	if readErr != nil {
		logger.Err(readErr).Str("path", fullKey).Msg("failed to read metadata bytes")
		return nil, readErr
	}
	return data, nil
}

func (b *Store[T, TMsg]) GetContents(ctx context.Context, key string) ([]byte, error) {
	key = b.objectPath(key)
	return b.get(ctx, key)
}

func (b *Store[T, TMsg]) GetMetadata(ctx context.Context, key string) ([]byte, error) {
	key = b.metadataPath(key)
	return b.get(ctx, key)
}

func newProtoMessage[T proto.Message]() T {
	var zero T
	t := reflect.TypeOf(zero)
	if t.Kind() == reflect.Pointer {
		return reflect.New(t.Elem()).Interface().(T)
	}
	return zero
}
