package blob

import (
	"context"
	"errors"
	"io"
	"path"
	"strings"

	gblob "gocloud.dev/blob"

	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/pkg/iterutil"
	"github.com/pomerium/pomerium/pkg/storage/blob/drivers"
)

const Separator = "/"

type ListOptions struct {
	finalizedRecordingsOnly bool
	FullPrefix              string
	listDrivers             []drivers.ListDriver
}

func (o *ListOptions) ApplyList(ctx context.Context, options *gblob.ListOptions) {
	for _, drs := range o.listDrivers {
		drs.ApplyList(ctx, options)
	}
	o.FullPrefix = options.Prefix
}

func defaultOptions(schema SchemaV1) *ListOptions {
	return &ListOptions{
		finalizedRecordingsOnly: false,
		listDrivers: append([]drivers.ListDriver{
			schema,
		}, drivers.DefaultListDrivers...),
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

func WithAdditionalListDrivers(drs ...drivers.ListDriver) ListOption {
	return func(o *ListOptions) {
		o.listDrivers = append(o.listDrivers, drs...)
	}
}

func IterateRecordingIDs(
	ctx context.Context,
	bucket *gblob.Bucket,
	schema SchemaV1,
	opts ...ListOption,
) iterutil.ErrorSeq[string] {
	options := defaultOptions(schema)
	options.apply(opts...)
	listOptions := &gblob.ListOptions{}
	options.ApplyList(ctx, listOptions)
	iter := bucket.List(listOptions)

	return func(yield func(string, error) bool) {
		for {
			obj, err := iter.Next(ctx)
			if errors.Is(err, io.EOF) {
				break
			}
			if err != nil {
				if !yield("", err) {
					return
				}
			}
			log.Ctx(ctx).Trace().Str("key", obj.Key).Msg("listing objects")

			if before, ok := strings.CutSuffix(obj.Key, ".proto"); ok {
				recordingID := path.Base(before)
				if recordingID == "" {
					continue
				}
				schemaWithID := SchemaV1WithKey{
					SchemaV1: schema,
					Key:      recordingID,
				}
				if options.finalizedRecordingsOnly {
					sigPath, _ := schemaWithID.SignaturePath()
					ok, err := bucket.Exists(ctx, sigPath)
					if err != nil || !ok {
						continue
					}
				}
				if !yield(recordingID, nil) {
					break
				}
			}
		}
	}
}
