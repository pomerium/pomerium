// Package grpcutil contains functions for interacting with gRPC.
package grpcutil

import (
	"context"
	"strings"

	"connectrpc.com/connect"
	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/proto"
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

// JWTMetadataKey is the key in the metadata.
const JWTMetadataKey = "jwt"

// WithOutgoingJWT appends a metadata header for the JWT to a context.
func WithOutgoingJWT(ctx context.Context, rawjwt string) context.Context {
	return metadata.AppendToOutgoingContext(ctx, JWTMetadataKey, rawjwt)
}

// JWTFromGRPCRequest returns the JWT from the gRPC request.
func JWTFromGRPCRequest(ctx context.Context) (rawjwt string, ok bool) {
	if callInfo, ok := connect.CallInfoForHandlerContext(ctx); ok {
		rawjwt := callInfo.RequestHeader().Get(JWTMetadataKey)
		if len(rawjwt) > 0 {
			return rawjwt, true
		}
	}

	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return "", false
	}

	rawjwts := md.Get(JWTMetadataKey)
	if len(rawjwts) == 0 {
		return "", false
	}

	return rawjwts[0], true
}

// GetTypeURL gets the TypeURL for a protobuf message.
func GetTypeURL(msg proto.Message) string {
	// taken from the anypb package
	const urlPrefix = "type.googleapis.com/"
	return urlPrefix + string(msg.ProtoReflect().Descriptor().FullName())
}

// this is a hack for detecting when envoy sends a codes.Internal with RST stream with & http2 code NO_ERROR
// to clients that are still active
func IsHTTP2NoErrorRST(err error) bool {
	if err == nil {
		return false
	}
	s := err.Error()
	return strings.Contains(s, "RST_STREAM") && strings.Contains(s, "NO_ERROR")
}
