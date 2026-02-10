package blob

import (
	"context"
	"io"
	"path"
	"sync"

	"github.com/rs/zerolog"
	"github.com/thanos-io/objstore"

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

type Store struct {
	ctx             context.Context
	mu              sync.Mutex
	installationUID string
	prefix          string
	bucket          objstore.Bucket
	*Options
}

func NewStore(
	ctx context.Context,
	prefix string,
	bucket objstore.Bucket,
	config *config.Config,
	opts ...Option,
) *Store {
	options := defaultOptions()

	options.Apply(opts...)

	b := &Store{
		ctx:     ctx,
		bucket:  bucket,
		prefix:  prefix,
		Options: options,
	}

	// TODO : we can probably instantiate the underlying bucket objstore in OnConfigChange
	b.OnConfigChange(ctx, config)
	return b
}

func (b *Store) Stop() {
	if err := b.bucket.Close(); err != nil {
		b.logger(b.ctx).Err(err).Msg("failed to close blob store bucket")
	}
}

func (b *Store) logger(ctx context.Context) *zerolog.Logger {
	l := log.Ctx(ctx).With().
		Str("component", "Store").
		Str("provider", string(b.bucket.Provider())).
		Logger()
	return &l
}

func (b *Store) objectPrefix() string {
	if b.includeInstallationID {
		return path.Join(b.prefix, b.installationUID)
	}
	return path.Join(b.prefix, noInstallationID)
}

func (b *Store) OnConfigChange(ctx context.Context, cfg *config.Config) {
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

func (b *Store) objectPath(key string) string {
	return path.Join(b.objectPrefix(), key)
}

func (b *Store) metadataPath(key string) string {
	return path.Join(b.objectPrefix(), key+".attrs")
}

func (b *Store) Put(ctx context.Context,
	key string,
	metadata io.Reader,
	contents io.Reader,
) error {
	if err := b.bucket.Upload(ctx, b.objectPath(key), contents); err != nil {
		b.logger(ctx).Err(err).Str("key", key).Msg("failed to upload contents")
		return err
	}
	if err := b.bucket.Upload(ctx, b.metadataPath(key), metadata); err != nil {
		b.logger(ctx).Err(err).Str("key", key).Msg("failed to upload metadata")
		return err
	}
	return nil
}

func (b *Store) GetContents(ctx context.Context, key string) ([]byte, error) {
	key = b.objectPath(key)
	rc, err := b.bucket.Get(ctx, key)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err := rc.Close(); err != nil {
			b.logger(ctx).Err(err).Str("key", key).Msg("failed to close blob")
		}
	}()
	return io.ReadAll(rc)
}

func (b *Store) GetMetadata(ctx context.Context, key string) ([]byte, error) {
	key = b.metadataPath(key)
	rc, err := b.bucket.Get(ctx, key)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err := rc.Close(); err != nil {
			b.logger(ctx).Err(err).Str("key", key).Msg("failed to close blob")
		}
	}()
	return io.ReadAll(rc)
}

func (b *Store) QueryMetadata(_ context.Context) ([]string, error) {
	// TODO : should use a proto decoder here and them the storage.backend filter expressions
	// on protobufs
	panic("implement me")
}
