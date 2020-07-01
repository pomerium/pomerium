// Package grpcutil contains functions for interacting with gRPC.
package grpcutil

import (
	"context"

	"google.golang.org/grpc/metadata"
)

// SessionIDMetadataKey is the key in the metadata.
const SessionIDMetadataKey = "sessionid"

// WithOutgoingSessionID appends a metadata header for the session ID to a context.
func WithOutgoingSessionID(ctx context.Context, sessionID string) context.Context {
	return metadata.AppendToOutgoingContext(ctx, SessionIDMetadataKey, sessionID)
}

// SessionIDFromGRPCRequest returns the session id from the gRPC request.
func SessionIDFromGRPCRequest(ctx context.Context) (sessionID string, ok bool) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return "", false
	}

	sessionIDs := md.Get(SessionIDMetadataKey)
	if len(sessionIDs) == 0 {
		return "", false
	}

	return sessionIDs[0], true
}
