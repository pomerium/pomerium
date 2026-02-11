package blob

import (
	"context"
	"fmt"
	"path"
	"strings"

	"github.com/thanos-io/objstore"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	"github.com/pomerium/pomerium/pkg/storage"
)

type QueryOptions struct {
	installationID string
	filter         storage.FilterExpression
	orderby        storage.OrderBy
}

func (o *QueryOptions) Apply(opts ...QueryOption) {
	for _, opt := range opts {
		opt(o)
	}
}

type QueryOption func(o *QueryOptions)

func WithQueryInstallationID(instID string) QueryOption {
	return func(o *QueryOptions) {
		o.installationID = instID
	}
}

func WithQueryFilter(expr storage.FilterExpression) QueryOption {
	return func(o *QueryOptions) {
		o.filter = expr
	}
}

func WithQueryOrderBy(ord storage.OrderBy) QueryOption {
	return func(o *QueryOptions) {
		o.orderby = ord
	}
}

func (b *Store[T, TMsg]) fetchQueryPaths(ctx context.Context, options *QueryOptions) ([]string, error) {
	// TODO : maybe we want to include multiple installation IDs here?
	scanPrefix := b.prefix
	if options.installationID != "" {
		scanPrefix = path.Join(b.prefix, options.installationID)
	}
	var attrPaths []string
	bucket, err := b.getBucket()
	if err != nil {
		return nil, err
	}
	err = bucket.Iter(ctx, scanPrefix, func(name string) error {
		if strings.HasSuffix(name, ".attrs") {
			attrPaths = append(attrPaths, name)
		}
		return nil
	}, objstore.WithRecursiveIter())
	if err != nil {
		return nil, fmt.Errorf("iterating metadata: %w", err)
	}
	return attrPaths, nil
}

func (b *Store[T, TMsg]) matchesProto(data []byte, expr storage.FilterExpression) (TMsg, bool, error) {
	md := newProtoMessage[TMsg]()
	if err := proto.Unmarshal(data, md); err != nil {
		// treat this as not a match since this means proto format is incompatible
		return md, false, nil
	}
	if expr == nil {
		return md, true, nil
	}
	match, err := matchesFilterExpression(md, expr)
	return md, match, err
}

// TODO : these will probably be expensive probably worth figuring out a cache mechanism, like the layering we do with databroker records
func (b *Store[T, TMsg]) QueryMetadata(
	ctx context.Context,
	opts ...QueryOption,
) ([]TMsg, error) {
	options := &QueryOptions{}
	options.Apply(opts...)

	mdPaths, err := b.fetchQueryPaths(ctx, options)
	if err != nil {
		b.logger(ctx).Err(err).Msg("failed to fetch metadata paths from blob store")
		return nil, err
	}

	var results []TMsg
	for _, mdPath := range mdPaths {
		logger := b.loggerForKey(ctx, mdPath)
		data, err := b.get(ctx, mdPath)
		if err != nil {
			continue
		}

		res, match, err := b.matchesProto(data, options.filter)
		if err != nil {
			logger.Err(err).Msg("failed to match protobuf to expression")
			return nil, err
		}
		if !match {
			logger.Trace().Msg("key did not match")
			continue
		}
		results = append(results, res)
	}
	if options.orderby != nil {
		if err := storage.SortStable(results, options.orderby); err != nil {
			return nil, status.Error(codes.InvalidArgument, fmt.Sprintf("invalid order by for message: %s", err.Error()))
		}
	}

	return results, nil
}
