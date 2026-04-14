package providers

import (
	"context"
	"net/http"
	"testing"

	"cloud.google.com/go/storage"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	azruntime "github.com/Azure/azure-sdk-for-go/sdk/azcore/runtime"
	s3manager "github.com/aws/aws-sdk-go-v2/feature/s3/manager"
	awss3 "github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/googleapis/gax-go/v2/callctx"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	gblob "gocloud.dev/blob"

	"github.com/pomerium/pomerium/pkg/storage/blob/middleware"
)

// auditOp abstracts running an audit middleware and extracting its results.
type auditOp struct {
	name string
	// run executes the middleware and returns the mutated context and BeforeXxx callback.
	run func(ctx context.Context) (context.Context, func(func(any) bool) error, error)
}

var auditOps = []auditOp{
	{"list", func(ctx context.Context) (context.Context, func(func(any) bool) error, error) {
		op := &middleware.ListOp{Ctx: ctx, Opts: &gblob.ListOptions{}}
		err := AuditLogListMiddleware(op)
		return op.Ctx, op.Opts.BeforeList, err
	}},
	{"read", func(ctx context.Context) (context.Context, func(func(any) bool) error, error) {
		op := &middleware.ReadOp{Ctx: ctx, Opts: &gblob.ReaderOptions{}}
		err := AuditLogReaderMiddleware(op)
		return op.Ctx, op.Opts.BeforeRead, err
	}},
	{"write", func(ctx context.Context) (context.Context, func(func(any) bool) error, error) {
		op := &middleware.WriteOp{Ctx: ctx, Opts: &gblob.WriterOptions{}}
		err := AuditLogWriterMiddleware(op)
		return op.Ctx, op.Opts.BeforeWrite, err
	}},
}

func TestAuditLogMiddleware(t *testing.T) {
	t.Parallel()
	const identity = "user@example.com"

	t.Run("requires identity", func(t *testing.T) {
		for _, tc := range auditOps {
			_, _, err := tc.run(context.Background())
			assert.ErrorIs(t, err, middleware.ErrBlobIdentityRequired, tc.name)
		}
	})

	ctx := middleware.ContextWithBlobUserAgent(context.Background(), identity)

	t.Run("sets GCS audit header", func(t *testing.T) {
		for _, tc := range auditOps {
			gotCtx, _, err := tc.run(ctx)
			require.NoError(t, err, tc.name)
			headers := callctx.HeadersFromContext(gotCtx)
			assert.Equal(t, []string{identity}, headers["x-goog-custom-audit-pomerium-user"], tc.name)
		}
	})

	t.Run("sets Azure UserAgent header", func(t *testing.T) {
		for _, tc := range auditOps {
			gotCtx, _, err := tc.run(ctx)
			require.NoError(t, err, tc.name)
			got := testAzureHeaderFromContext(t, gotCtx)
			assert.Equal(t, identity, got.Get(HeaderUserAgent), tc.name)
		}
	})

	t.Run("sets S3 AppID", func(t *testing.T) {
		for _, tc := range auditOps {
			_, before, err := tc.run(ctx)
			require.NoError(t, err, tc.name)

			var opts []func(*awss3.Options)
			before(func(target any) bool {
				if p, ok := target.(**[]func(*awss3.Options)); ok {
					*p = &opts
					return true
				}
				return false
			})
			require.Len(t, opts, 1, tc.name)
			var s3Opts awss3.Options
			opts[0](&s3Opts)
			assert.Equal(t, identity, s3Opts.AppID, tc.name)
		}
	})

	t.Run("sets S3 uploader options on write", func(t *testing.T) {
		op := &middleware.WriteOp{Ctx: ctx, Opts: &gblob.WriterOptions{}}
		require.NoError(t, AuditLogWriterMiddleware(op))

		var uploader s3manager.Uploader
		op.Opts.BeforeWrite(func(target any) bool {
			if p, ok := target.(**s3manager.Uploader); ok {
				*p = &uploader
				return true
			}
			return false
		})
		require.Len(t, uploader.ClientOptions, 1)
		var s3Opts awss3.Options
		uploader.ClientOptions[0](&s3Opts)
		assert.Equal(t, identity, s3Opts.AppID)
	})
}

//revive:disable-next-line:context-as-argument
func testAzureHeaderFromContext(t *testing.T, ctx context.Context) http.Header {
	t.Helper()
	var captured http.Header
	pl := azruntime.NewPipeline("test", "v0.0.0", azruntime.PipelineOptions{}, &policy.ClientOptions{
		Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			captured = req.Header.Clone()
			return &http.Response{StatusCode: http.StatusOK, Body: http.NoBody}, nil
		}),
	})
	req, err := azruntime.NewRequest(ctx, http.MethodGet, "https://localhost")
	require.NoError(t, err)
	_, err = pl.Do(req)
	require.NoError(t, err)
	return captured
}

// roundTripFunc adapts a function to the policy.Transporter interface.
type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) Do(req *http.Request) (*http.Response, error) { return f(req) }

func TestListOptimizationMiddleware_SetsGCSProjectionNoACL(t *testing.T) {
	t.Parallel()
	op := &middleware.ListOp{Ctx: context.Background(), Opts: &gblob.ListOptions{}}
	require.NoError(t, ListOptimizationMiddleware(op))

	query := &storage.Query{}
	op.Opts.BeforeList(func(target any) bool {
		if q, ok := target.(*storage.Query); ok {
			*q = *query
			query = q
			return true
		}
		return false
	})
	assert.Equal(t, storage.ProjectionNoACL, query.Projection)
}
