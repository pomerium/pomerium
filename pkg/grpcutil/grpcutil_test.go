package grpcutil

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"google.golang.org/grpc/metadata"
)

func TestWithOutgoingSessionID(t *testing.T) {
	ctx := context.Background()
	ctx = WithOutgoingSessionID(ctx, "EXAMPLE")
	md, ok := metadata.FromOutgoingContext(ctx)
	if !assert.True(t, ok) {
		return
	}
	assert.Equal(t, []string{"EXAMPLE"}, md.Get("sessionid"))
}

func TestSessionIDFromGRPCRequest(t *testing.T) {
	ctx := context.Background()
	ctx = metadata.NewIncomingContext(ctx, metadata.MD{
		"sessionid": {"EXAMPLE"},
	})
	sessionID, ok := SessionIDFromGRPCRequest(ctx)
	assert.True(t, ok)
	assert.Equal(t, "EXAMPLE", sessionID)
}
