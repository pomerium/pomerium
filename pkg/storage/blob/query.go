package blob

import (
	"context"
	"fmt"
	"path"
	"slices"
	"strings"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/fieldmaskpb"

	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/pkg/protoutil"
	"github.com/pomerium/pomerium/pkg/storage"
)

type QueryOptions struct {
	installationID string
	filter         storage.FilterExpression
	orderby        storage.OrderBy
	// default is 25
	limit  int
	offset int
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

func WithQueryOffset(offset int) QueryOption {
	return func(o *QueryOptions) {
		o.offset = offset
	}
}

func WithQueryLimit(limit int) QueryOption {
	return func(o *QueryOptions) {
		o.limit = limit
	}
}

type queryPath struct {
	objectPath string
	objectID   string
}

func (b *Store[T, TMsg]) fetchQueryPaths(ctx context.Context, recordingType string, options *QueryOptions) ([]queryPath, error) {
	schema := b.schema(recordingType)
	scanPrefix := schema.basePath()
	var attrPaths []queryPath
	bucket, err := b.getBucket()
	if err != nil {
		return nil, err
	}
	err = bucket.Iter(ctx, scanPrefix, func(name string) error {
		log.Ctx(ctx).Info().Str("scanPrefix", scanPrefix).Str("name", name).Msg("DEBUG")
		if strings.HasSuffix(name, ".attrs") {
			attrPaths = append(attrPaths, queryPath{
				objectPath: name,
				objectID:   path.Base(strings.TrimSuffix(name, ".attrs")),
			})
		}
		return nil
	})
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

type MetadataWithId[T any, TMsg interface {
	*T
	proto.Message
}] struct {
	Id string
	Md TMsg
}

func (b *Store[T, TMsg]) QueryMetadata(
	ctx context.Context,
	recordingType string,
	opts ...QueryOption,
) ([]MetadataWithId[T, TMsg], error) {
	options := &QueryOptions{
		limit: 25,
	}
	options.Apply(opts...)

	mdPaths, err := b.fetchQueryPaths(ctx, recordingType, options)
	if err != nil {
		b.logger(ctx).Err(err).Msg("failed to fetch metadata paths from blob store")
		return nil, err
	}

	var results []MetadataWithId[T, TMsg]
	for _, mdPath := range mdPaths {
		logger := b.loggerForKey(ctx, mdPath.objectPath)
		data, err := b.get(ctx, mdPath.objectPath)
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
		results = append(results, MetadataWithId[T, TMsg]{
			Id: mdPath.objectID,
			Md: res,
		})
	}
	if options.orderby != nil {
		fns := make([]protoutil.CompareFunc[TMsg], len(options.orderby))
		for i, item := range options.orderby {
			cmp, err := protoutil.CompareFuncForFieldMask[T, TMsg](&fieldmaskpb.FieldMask{
				Paths: []string{item.Field},
			})
			if err != nil {
				return nil, status.Error(codes.InvalidArgument, fmt.Sprintf("invalid order by for message: %s", err.Error()))
			}
			ascending := item.Ascending
			fns[i] = func(x, y TMsg) int {
				v := cmp(x, y)
				if !ascending {
					v = -v
				}
				return v
			}
		}
		slices.SortStableFunc(results, func(a, b MetadataWithId[T, TMsg]) int {
			for _, fn := range fns {
				if v := fn(a.Md, b.Md); v != 0 {
					return v
				}
			}
			return 0
		})
	}

	if options.offset >= 0 {
		if options.offset >= len(results) {
			return []MetadataWithId[T, TMsg]{}, nil
		}
		results = results[options.offset:]
	}
	if options.limit >= 0 {
		if options.limit >= len(results) {
			return results, nil
		}
		return results[:options.limit], nil
	}
	return results, nil
}
