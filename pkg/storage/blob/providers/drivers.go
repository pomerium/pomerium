//nolint:revive
package providers

import (
	"context"
	"net/http"

	"cloud.google.com/go/storage"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
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

func addAuditIdentity(ctx context.Context, asFunc func(any) bool) error {
	identity, ok := drivers.BlobUserAgentFromContext(ctx)
	if !ok {
		return drivers.ErrBlobIdentityRequired
	}
	ctx = policy.WithHTTPHeader(ctx, http.Header{
		"UserAgent": []string{identity},
	})
	var s3Opts *[]func(*awss3.Options)
	if asFunc(&s3Opts) {
		*s3Opts = append(*s3Opts, s3UserAgentOption(identity))
	}
	var uploader *s3manager.Uploader
	if asFunc(&uploader) {
		uploader.ClientOptions = append(uploader.ClientOptions, s3UserAgentOption(identity))
	}
	return nil
}

type AuditLogListDriver struct{}

func (dr AuditLogListDriver) ApplyList(ctx context.Context, options *gblob.ListOptions) {
	drivers.HandleMutateBeforeList(options, func(asFunc func(any) bool) error {
		return addAuditIdentity(ctx, asFunc)
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
type AuditLogReaderDriver struct{}

func (dr AuditLogReaderDriver) ApplyReader(ctx context.Context, options *gblob.ReaderOptions) {
	drivers.HandleMutateBeforeRead(options, func(asFunc func(any) bool) error {
		return addAuditIdentity(ctx, asFunc)
	})
}

// AuditLogWriterDriver sets per request metadata that identifies users in blob audit logs
type AuditLogWriterDriver struct{}

func (dr AuditLogWriterDriver) ApplyWriter(ctx context.Context, options *gblob.WriterOptions) {
	drivers.HandleMutateBeforeWrite(options, func(asFunc func(any) bool) error {
		return addAuditIdentity(ctx, asFunc)
	})
}
