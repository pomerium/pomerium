package blob

import (
	"context"
	"errors"
	"fmt"
	"io"
	"path"
	"strings"

	gblob "gocloud.dev/blob"

	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/pkg/iterutil"
	"github.com/pomerium/pomerium/pkg/storage/blob/middleware"
)

const Separator = "/"

type ListOptions struct {
	finalizedRecordingsOnly bool
	middleware              []middleware.ListMiddleware
}

func defaultListOptions(schema SchemaV1) *ListOptions {
	return &ListOptions{
		finalizedRecordingsOnly: false,
		middleware: append([]middleware.ListMiddleware{
			schema.ListMiddleware(),
		}, middleware.DefaultListMiddleware...),
	}
}

type ListOption func(o *ListOptions)

func (o *ListOptions) apply(opts ...ListOption) {
	for _, opt := range opts {
		opt(o)
	}
}

func WithFinalizedRecordings() ListOption {
	return func(o *ListOptions) {
		o.finalizedRecordingsOnly = true
	}
}

func WithAdditionalListMiddleware(mws ...middleware.ListMiddleware) ListOption {
	return func(o *ListOptions) {
		o.middleware = append(o.middleware, mws...)
	}
}

func IterateRecordingIDs(
	ctx context.Context,
	bucket *gblob.Bucket,
	schema SchemaV1,
	opts ...ListOption,
) iterutil.ErrorSeq[string] {
	options := defaultListOptions(schema)
	options.apply(opts...)

	op := &middleware.ListOp{
		Ctx:  ctx,
		Opts: &gblob.ListOptions{},
	}
	for _, mw := range options.middleware {
		if err := mw(op); err != nil {
			return func(yield func(string, error) bool) {
				yield("", fmt.Errorf("list middleware: %w", err))
			}
		}
	}

	iter := bucket.List(op.Opts)

	return func(yield func(string, error) bool) {
		for {
			obj, err := iter.Next(op.Ctx)
			if errors.Is(err, io.EOF) {
				break
			}
			if err != nil {
				yield("", err)
				return
			}
			log.Ctx(op.Ctx).Trace().Str("key", obj.Key).Msg("listing objects")

			if !obj.IsDir {
				continue
			}
			recordingID := path.Base(strings.TrimSuffix(obj.Key, Separator))
			if recordingID == "" {
				continue
			}
			schemaWithID := SchemaV1WithKey{
				SchemaV1: schema,
				Key:      recordingID,
			}
			if options.finalizedRecordingsOnly {
				sigPath, _ := schemaWithID.SignaturePath()
				ok, err := bucket.Exists(op.Ctx, sigPath)
				if err != nil {
					if !yield("", fmt.Errorf("check signature for %s: %w", recordingID, err)) {
						return
					}
					continue
				}
				if !ok {
					continue
				}
			}
			if !yield(recordingID, nil) {
				break
			}
		}
	}
}
