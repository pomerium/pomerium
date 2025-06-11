package grpcutil

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"google.golang.org/grpc/metadata"
)

func TestWithOutgoingSessionID(t *testing.T) {
	ctx := t.Context()
	ctx = WithOutgoingSessionID(ctx, "EXAMPLE")
	md, ok := metadata.FromOutgoingContext(ctx)
	if !assert.True(t, ok) {
		return
	}
	assert.Equal(t, []string{"EXAMPLE"}, md.Get("sessionid"))
}

func TestSessionIDFromGRPCRequest(t *testing.T) {
	ctx := t.Context()
	ctx = metadata.NewIncomingContext(ctx, metadata.MD{
		"sessionid": {"EXAMPLE"},
	})
	sessionID, ok := SessionIDFromGRPCRequest(ctx)
	assert.True(t, ok)
	assert.Equal(t, "EXAMPLE", sessionID)
}

func TestWithOutgoingJWT(t *testing.T) {
	rawjwt := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
	ctx := t.Context()
	ctx = WithOutgoingJWT(ctx, rawjwt)
	md, ok := metadata.FromOutgoingContext(ctx)
	if !assert.True(t, ok) {
		return
	}
	assert.Equal(t, []string{rawjwt}, md.Get("jwt"))
}

func TestJWTFromGRPCRequest(t *testing.T) {
	rawjwt := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
	ctx := t.Context()
	ctx = metadata.NewIncomingContext(ctx, metadata.MD{
		"jwt": {rawjwt},
	})
	found, ok := JWTFromGRPCRequest(ctx)
	assert.True(t, ok)
	assert.Equal(t, rawjwt, found)
}
