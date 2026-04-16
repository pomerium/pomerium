package middleware

import (
	"context"
	"errors"
)

var ErrBlobIdentityRequired = errors.New("identity is required to access blob store")

type blobUserAgentContextKey struct{}

func ContextWithBlobUserAgent(ctx context.Context, userAgent string) context.Context {
	return context.WithValue(ctx, &blobUserAgentContextKey{}, userAgent)
}

func BlobUserAgentFromContext(ctx context.Context) (string, bool) {
	val := ctx.Value(&blobUserAgentContextKey{})
	if val == nil {
		return "", false
	}
	return val.(string), true
}

type blobAccessIDContextKey struct{}

func ContextWithAccessID(ctx context.Context, accessID string) context.Context {
	return context.WithValue(ctx, &blobAccessIDContextKey{}, accessID)
}

func BlobAccessIDFromContext(ctx context.Context) *string {
	val := ctx.Value(&blobAccessIDContextKey{})
	if val == nil {
		return nil
	}
	ret := val.(string)
	return &ret
}
