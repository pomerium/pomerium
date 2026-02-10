package blob

import (
	"context"
	"fmt"
	"io"
	"path"
	"reflect"
	"slices"
	"sync"

	"github.com/rs/zerolog"
	"github.com/thanos-io/objstore"
	"google.golang.org/protobuf/proto"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/log"
)

type Options struct {
	includeInstallationID bool
}

func (o *Options) Apply(opts ...Option) {
	for _, opt := range opts {
		opt(o)
	}
}

func defaultOptions() *Options {
	return &Options{
		includeInstallationID: false,
	}
}

type Option func(o *Options)

func WithIncludeInstallationID() Option {
	return func(o *Options) {
		o.includeInstallationID = true
	}
}

const noInstallationID = "__global"

type Store[Md proto.Message] struct {
	ctx             context.Context
	mu              sync.Mutex
	installationUID string
	prefix          string
	bucket          objstore.Bucket
	*Options
}

func NewStore[T proto.Message](
	ctx context.Context,
	prefix string,
	bucket objstore.Bucket,
	config *config.Config,
	opts ...Option,
) (*Store[T], error) {
	options := defaultOptions()

	options.Apply(opts...)

	b := &Store[T]{
		ctx:     ctx,
		bucket:  bucket,
		prefix:  prefix,
		Options: options,
	}

	// TODO : we can probably instantiate the underlying bucket objstore in OnConfigChange
	b.OnConfigChange(ctx, config)

	if !slices.Contains(b.bucket.SupportedIterOptions(), objstore.Recursive) {
		return nil, fmt.Errorf("remote blob store must suppored recursive iteration")
	}
	return b, nil
}

func (b *Store[Md]) Stop() {
	b.mu.Lock()
	b.closeLocked()
	b.mu.Unlock()
}

func (b *Store[Md]) closeLocked() {
	if err := b.bucket.Close(); err != nil {
		b.logger(b.ctx).Err(err).Msg("failed to close blob store bucket")
	}
}

func (b *Store[Md]) Querier() ObjectQuerier[Md] {
	return b
}

func (b *Store[Md]) Writer() ObjectWriter {
	return b
}

func (b *Store[Md]) Reader() ObjectReader {
	return b
}

func (b *Store[Md]) logger(ctx context.Context) *zerolog.Logger {
	l := log.Ctx(ctx).With().
		Str("component", "Store").
		Str("provider", string(b.bucket.Provider())).
		Logger()
	return &l
}

func (b *Store[Md]) loggerForKey(ctx context.Context, key string) *zerolog.Logger {
	l := log.Ctx(ctx).With().
		Str("component", "Store").
		Str("provider", string(b.bucket.Provider())).
		Str("key", key).
		Logger()
	return &l
}

func (b *Store[Md]) objectPrefix() string {
	if b.includeInstallationID {
		return path.Join(b.prefix, b.installationUID)
	}
	return path.Join(b.prefix, noInstallationID)
}

func (b *Store[Md]) OnConfigChange(ctx context.Context, cfg *config.Config) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.installationUID != cfg.Options.InstallationID {
		b.logger(ctx).
			Warn().Str("incoming", cfg.Options.InstallationID).
			Str("previous", b.installationUID).
			Msg("installation id has changed")
	}
	b.installationUID = cfg.Options.InstallationID
}

func (b *Store[Md]) objectPath(key string) string {
	return path.Join(b.objectPrefix(), key)
}

func (b *Store[Md]) metadataPath(key string) string {
	return path.Join(b.objectPrefix(), key+".attrs")
}

func (b *Store[Md]) Put(ctx context.Context,
	key string,
	metadata io.Reader,
	contents io.Reader,
) error {
	objKey := b.objectPath(key)
	mdKey := b.metadataPath(key)
	if err := b.bucket.Upload(ctx, b.objectPath(key), contents); err != nil {
		b.loggerForKey(ctx, objKey).Err(err).Msg("failed to upload contents")
		return err
	}
	if err := b.bucket.Upload(ctx, b.metadataPath(key), metadata); err != nil {
		b.loggerForKey(ctx, mdKey).Err(err).Str("key", key).Msg("failed to upload metadata")
		return err
	}
	return nil
}

func (b *Store[Md]) get(ctx context.Context, fullKey string) ([]byte, error) {
	logger := b.loggerForKey(ctx, fullKey)
	rc, err := b.bucket.Get(ctx, fullKey)
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

func (b *Store[Md]) GetContents(ctx context.Context, key string) ([]byte, error) {
	key = b.objectPath(key)
	return b.get(ctx, key)
}

func (b *Store[Md]) GetMetadata(ctx context.Context, key string) ([]byte, error) {
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
