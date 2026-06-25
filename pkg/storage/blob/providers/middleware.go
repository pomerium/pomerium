//nolint:revive
package providers

import (
	"context"
	"fmt"
	"net/http"

	"cloud.google.com/go/storage"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	s3manager "github.com/aws/aws-sdk-go-v2/feature/s3/manager"
	awss3 "github.com/aws/aws-sdk-go-v2/service/s3"
	smithymiddleware "github.com/aws/smithy-go/middleware"
	smithyhttp "github.com/aws/smithy-go/transport/http"
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
	HeaderUserAgent = "User-Agent"
)

type azureAuditHeaderKey struct{}

func withAzureAuditHeaders(ctx context.Context, h http.Header) context.Context {
	return context.WithValue(ctx, azureAuditHeaderKey{}, h)
}

// azureAuditHeaderPolicy copies per-request audit headers onto the outgoing
// request before the blob operation has been signed
type azureAuditHeaderPolicy struct{}

func (azureAuditHeaderPolicy) Do(req *policy.Request) (*http.Response, error) {
	if h, ok := req.Raw().Context().Value(azureAuditHeaderKey{}).(http.Header); ok {
		for k, vals := range h {
			req.Raw().Header[http.CanonicalHeaderKey(k)] = vals
		}
	}
	return req.Next()
}

// createAuditContext adds context values for GCS & Azure blob header UserAgent values.
func createAuditContext(ctx context.Context, identity string, accessID *string) context.Context {
	azureHeaders := http.Header{
		HeaderUserAgent: []string{identity},
	}
	googHeaders := []string{
		"x-goog-custom-audit-pomerium-user", identity,
	}
	// optional accessID header
	if accessID != nil {
		azureHeaders["x-ms-client-request-id"] = []string{*accessID}
		googHeaders = append(googHeaders,
			"x-goog-custom-audit-pomerium-access-id", *accessID,
		)
	}
	ctx = withAzureAuditHeaders(ctx, azureHeaders)
	ctx = callctx.SetHeaders(ctx, googHeaders...)
	return ctx
}

// addS3AuditIdentity sets per-operation S3 options that inject the user identity
// into CloudTrail audit logs via the AppID field.
func addS3AuditIdentity(asFunc func(any) bool, identity string, accessID *string) {
	var s3Opts *[]func(*awss3.Options)
	if asFunc(&s3Opts) {
		*s3Opts = append(*s3Opts, s3UserAgentOption(identity))
		if accessID != nil {
			*s3Opts = append(*s3Opts, s3CustomQueryParam("pomerium_access_id", *accessID))
		}
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

// s3CustomQueryParam returns an S3 per-operation option that adds a query
// parameter to the outgoing request. The parameter is added in the Build
// step of the SDK middleware stack, which runs before SigV4 signing in the
// Finalize step — so additional parameters included here also show up in
// the signed canonical request.
// Mutating the URL after signing (e.g. via a custom HTTPClient) would break
// strict SigV4 verifiers such as MinIO,Ceph,etc...
func s3CustomQueryParam(key, val string) func(*awss3.Options) {
	return func(o *awss3.Options) {
		o.APIOptions = append(o.APIOptions, func(stack *smithymiddleware.Stack) error {
			return stack.Build.Add(addQueryParamMiddleware(key, val), smithymiddleware.After)
		})
	}
}

func addQueryParamMiddleware(key, val string) smithymiddleware.BuildMiddleware {
	return smithymiddleware.BuildMiddlewareFunc(
		fmt.Sprintf("pomerium.AddS3QueryParam(%s)", key),
		func(ctx context.Context, in smithymiddleware.BuildInput, next smithymiddleware.BuildHandler) (smithymiddleware.BuildOutput, smithymiddleware.Metadata, error) {
			if req, ok := in.Request.(*smithyhttp.Request); ok && req.URL != nil {
				q := req.URL.Query()
				q.Add(key, val)
				req.URL.RawQuery = q.Encode()
			}
			return next.HandleBuild(ctx, in)
		},
	)
}

// auditIdentity extracts the blob user identity from context and enriches it
// with provider-specific audit headers (Azure, GCS).
func auditIdentity(ctx context.Context) (outCtx context.Context, identity string, accessID *string, err error) {
	identity, ok := middleware.BlobUserAgentFromContext(ctx)
	if !ok {
		return ctx, "", nil, middleware.ErrBlobIdentityRequired
	}
	accessID = middleware.BlobAccessIDFromContext(ctx)
	return createAuditContext(ctx, identity, middleware.BlobAccessIDFromContext(ctx)), identity, accessID, nil
}

// s3AuditBeforeFunc returns a BeforeXxx callback that injects the identity
// into S3 per-operation options for CloudTrail audit logging
func s3AuditBeforeFunc(identity string, accessID *string) func(asFunc func(any) bool) error {
	return func(asFunc func(any) bool) error {
		addS3AuditIdentity(asFunc, identity, accessID)
		return nil
	}
}

// AuditLogListMiddleware sets per-request metadata that identifies users in blob audit logs for list operations.
func AuditLogListMiddleware(op *middleware.ListOp) error {
	ctx, identity, accessID, err := auditIdentity(op.Ctx)
	if err != nil {
		return err
	}
	op.Ctx = ctx
	middleware.HandleMutateBeforeList(op.Opts, s3AuditBeforeFunc(identity, accessID))
	return nil
}

// AuditLogReaderMiddleware sets per-request metadata that identifies users in blob audit logs for read operations.
func AuditLogReaderMiddleware(op *middleware.ReadOp) error {
	ctx, identity, accessID, err := auditIdentity(op.Ctx)
	if err != nil {
		return err
	}
	op.Ctx = ctx
	middleware.HandleMutateBeforeRead(op.Opts, s3AuditBeforeFunc(identity, accessID))
	return nil
}

// AuditLogWriterMiddleware sets per-request metadata that identifies users in blob audit logs for write operations.
func AuditLogWriterMiddleware(op *middleware.WriteOp) error {
	ctx, identity, accessID, err := auditIdentity(op.Ctx)
	if err != nil {
		return err
	}
	op.Ctx = ctx
	middleware.HandleMutateBeforeWrite(op.Opts, s3AuditBeforeFunc(identity, accessID))
	return nil
}
