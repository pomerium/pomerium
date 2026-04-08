//nolint:revive
package providers

import (
	"context"

	"cloud.google.com/go/storage"
	s3manager "github.com/aws/aws-sdk-go-v2/feature/s3/manager"
	awss3 "github.com/aws/aws-sdk-go-v2/service/s3"
	gblob "gocloud.dev/blob"
	_ "gocloud.dev/blob/fileblob"
	_ "gocloud.dev/blob/memblob"

	"github.com/pomerium/pomerium/pkg/storage/blob/drivers"
)

func init() {
	drivers.RegisterListDrivers(ListOptimizationDriver{})
	drivers.RegisterReaderDriver(AuditLogReaderDriver{})
	drivers.RegisterWriterDriver(AuditLogWriterDriver{})
}

type ListOptimizationDriver struct{}

func (c ListOptimizationDriver) ApplyList(_ context.Context, options *gblob.ListOptions) {
	drivers.HandleMutateBeforeList(options, func(asFunc func(any) bool) error {
		gcsQuery := &storage.Query{}
		if asFunc(gcsQuery) {
			gcsQuery.Projection = storage.ProjectionNoACL
		}
		return nil
	})
}

// s3UserAgentOption returns an S3 per-operation option that sets the AppID
// field, which the AWS SDK appends to the User-Agent header. This identity
// then appears in CloudTrail audit logs.
func s3UserAgentOption(identity string) func(*awss3.Options) {
	return func(o *awss3.Options) {
		o.AppID = identity
	}
}

// AuditLogReaderDriver sets per request metadata that identifies users in blob audit logs
// Note: currently only the s3 blob driver can set per-request metadata that shows up in audit logs.
// For GCS & Azure, the blob constructors have been wrapped to the blob stores with useragent headers for
// all requests - see useragent.go.
type AuditLogReaderDriver struct{}

func (dr AuditLogReaderDriver) ApplyReader(ctx context.Context, options *gblob.ReaderOptions) {
	drivers.HandleMutateBeforeRead(options, func(asFunc func(any) bool) error {
		identity, ok := drivers.BlobUserAgentFromContext(ctx)
		if !ok {
			return drivers.ErrBlobIdentityRequired
		}
		var s3Opts *[]func(*awss3.Options)
		if asFunc(&s3Opts) {
			*s3Opts = append(*s3Opts, s3UserAgentOption(identity))
		}
		return nil
	})
}

// AuditLogWriterDriver sets per request metadata that identifies users in blob audit logs
// Note: currently only the s3 blob driver can set per-request metadata that shows up in audit logs.
// For GCS & Azure, the blob constructors have been wrapped to the blob stores with useragent headers for
// all requests - see useragent.go.
type AuditLogWriterDriver struct{}

func (dr AuditLogWriterDriver) ApplyWriter(ctx context.Context, options *gblob.WriterOptions) {
	drivers.HandleMutateBeforeWrite(options, func(asFunc func(any) bool) error {
		identity, ok := drivers.BlobUserAgentFromContext(ctx)
		if !ok {
			return drivers.ErrBlobIdentityRequired
		}
		var uploader *s3manager.Uploader
		if asFunc(&uploader) {
			uploader.ClientOptions = append(uploader.ClientOptions, s3UserAgentOption(identity))
		}
		return nil
	})
}
