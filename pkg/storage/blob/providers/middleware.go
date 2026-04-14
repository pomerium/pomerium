//nolint:revive
package providers

import (
	"context"
	"net/http"

	"cloud.google.com/go/storage"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	s3manager "github.com/aws/aws-sdk-go-v2/feature/s3/manager"
	awss3 "github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/googleapis/gax-go/v2/callctx"
	_ "gocloud.dev/blob/fileblob"
	_ "gocloud.dev/blob/memblob"

	"github.com/pomerium/pomerium/pkg/storage/blob/middleware"
)

func init() {
	middleware.RegisterListMiddleware(ListOptimizationMiddleware, AuditLogListMiddleware)
	middleware.RegisterReaderMiddleware(AuditLogReaderMiddleware)
	middleware.RegisterWriterMiddleware(AuditLogWriterMiddleware)
}

// ListOptimizationMiddleware sets ProjectionNoACL on GCS list queries to avoid
// fetching ACL metadata we don't need.
func ListOptimizationMiddleware(op *middleware.ListOp) error {
	middleware.HandleMutateBeforeList(op.Opts, func(asFunc func(any) bool) error {
		gcsQuery := &storage.Query{}
		if asFunc(gcsQuery) {
			gcsQuery.Projection = storage.ProjectionNoACL
		}
		return nil
	})
	return nil
}

const (
	HeaderUserAgent = "UserAgent"
)

// createAuditContext adds context values for GCS & Azure blob header UserAgent values.
func createAuditContext(ctx context.Context, identity string) context.Context {
	ctx = policy.WithHTTPHeader(ctx, http.Header{
		HeaderUserAgent: []string{identity},
	})
	ctx = callctx.SetHeaders(ctx, "x-goog-custom-audit-pomerium-user", identity)
	return ctx
}

// addS3AuditIdentity sets per-operation S3 options that inject the user identity
// into CloudTrail audit logs via the AppID field.
func addS3AuditIdentity(asFunc func(any) bool, identity string) {
	var s3Opts *[]func(*awss3.Options)
	if asFunc(&s3Opts) {
		*s3Opts = append(*s3Opts, s3UserAgentOption(identity))
	}
	var uploader *s3manager.Uploader
	if asFunc(&uploader) {
		uploader.ClientOptions = append(uploader.ClientOptions, s3UserAgentOption(identity))
	}
}

// s3UserAgentOption returns an S3 per-operation option that sets the AppID
// field, which the AWS SDK appends to the User-Agent header. This identity
// then appears in CloudTrail audit logs
func s3UserAgentOption(identity string) func(*awss3.Options) {
	return func(o *awss3.Options) {
		o.AppID = identity
	}
}

// auditIdentity extracts the blob user identity from context and enriches it
// with provider-specific audit headers (Azure, GCS).
func auditIdentity(ctx context.Context) (context.Context, string, error) {
	identity, ok := middleware.BlobUserAgentFromContext(ctx)
	if !ok {
		return ctx, "", middleware.ErrBlobIdentityRequired
	}
	return createAuditContext(ctx, identity), identity, nil
}

// s3AuditBeforeFunc returns a BeforeXxx callback that injects the identity
// into S3 per-operation options for CloudTrail audit logging
func s3AuditBeforeFunc(identity string) func(asFunc func(any) bool) error {
	return func(asFunc func(any) bool) error {
		addS3AuditIdentity(asFunc, identity)
		return nil
	}
}

// AuditLogListMiddleware sets per-request metadata that identifies users in blob audit logs for list operations.
func AuditLogListMiddleware(op *middleware.ListOp) error {
	ctx, identity, err := auditIdentity(op.Ctx)
	if err != nil {
		return err
	}
	op.Ctx = ctx
	middleware.HandleMutateBeforeList(op.Opts, s3AuditBeforeFunc(identity))
	return nil
}

// AuditLogReaderMiddleware sets per-request metadata that identifies users in blob audit logs for read operations.
func AuditLogReaderMiddleware(op *middleware.ReadOp) error {
	ctx, identity, err := auditIdentity(op.Ctx)
	if err != nil {
		return err
	}
	op.Ctx = ctx
	middleware.HandleMutateBeforeRead(op.Opts, s3AuditBeforeFunc(identity))
	return nil
}

// AuditLogWriterMiddleware sets per-request metadata that identifies users in blob audit logs for write operations.
func AuditLogWriterMiddleware(op *middleware.WriteOp) error {
	ctx, identity, err := auditIdentity(op.Ctx)
	if err != nil {
		return err
	}
	op.Ctx = ctx
	middleware.HandleMutateBeforeWrite(op.Opts, s3AuditBeforeFunc(identity))
	return nil
}
