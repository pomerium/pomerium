package grpcutil

import (
	"context"
	"encoding/base64"
	"fmt"
	"time"

	"github.com/go-jose/go-jose/v3"
	"github.com/go-jose/go-jose/v3/jwt"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/pomerium/pomerium/internal/log"
)

// WithStreamSignedJWT returns a StreamClientInterceptor that adds a JWT to requests.
func WithStreamSignedJWT(getKey func() []byte) grpc.StreamClientInterceptor {
	return func(
		ctx context.Context,
		desc *grpc.StreamDesc,
		cc *grpc.ClientConn,
		method string, streamer grpc.Streamer,
		opts ...grpc.CallOption,
	) (grpc.ClientStream, error) {
		ctx, err := WithSignedJWT(ctx, getKey())
		if err != nil {
			return nil, err
		}

		return streamer(ctx, desc, cc, method, opts...)
	}
}

// WithUnarySignedJWT returns a UnaryClientInterceptor that adds a JWT to requests.
func WithUnarySignedJWT(getKey func() []byte) grpc.UnaryClientInterceptor {
	return func(ctx context.Context, method string, req, reply any, cc *grpc.ClientConn, invoker grpc.UnaryInvoker, opts ...grpc.CallOption) error {
		ctx, err := WithSignedJWT(ctx, getKey())
		if err != nil {
			return err
		}

		return invoker(ctx, method, req, reply, cc, opts...)
	}
}

// WithSignedJWT adds a signed JWT to the context.
func WithSignedJWT(ctx context.Context, key []byte) (context.Context, error) {
	if len(key) > 0 {
		sig, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.HS256, Key: key},
			(&jose.SignerOptions{}).WithType("JWT"))
		if err != nil {
			return ctx, err
		}

		rawjwt, err := jwt.Signed(sig).Claims(jwt.Claims{
			Expiry: jwt.NewNumericDate(time.Now().Add(time.Hour)),
		}).CompactSerialize()
		if err != nil {
			return ctx, err
		}

		ctx = WithOutgoingJWT(ctx, rawjwt)
	}
	return ctx, nil
}

// UnaryRequireSignedJWT requires a JWT in the gRPC metadata and that it be signed by the base64-encoded key.
func UnaryRequireSignedJWT(key string) grpc.UnaryServerInterceptor {
	keyBS, _ := base64.StdEncoding.DecodeString(key)
	return func(ctx context.Context, req any, _ *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (resp any, err error) {
		if err := RequireSignedJWT(ctx, keyBS); err != nil {
			return nil, err
		}
		return handler(ctx, req)
	}
}

// StreamRequireSignedJWT requires a JWT in the gRPC metadata and that it be signed by the base64-encoded key.
func StreamRequireSignedJWT(key string) grpc.StreamServerInterceptor {
	keyBS, _ := base64.StdEncoding.DecodeString(key)
	return func(srv any, ss grpc.ServerStream, _ *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		if err := RequireSignedJWT(ss.Context(), keyBS); err != nil {
			return err
		}
		return handler(srv, ss)
	}
}

// RequireSignedJWT requires a JWT in the gRPC metadata and that it be signed by the given key.
func RequireSignedJWT(ctx context.Context, key []byte) error {
	if len(key) > 0 {
		rawjwt, ok := JWTFromGRPCRequest(ctx)
		if !ok {
			return status.Error(codes.Unauthenticated, "unauthenticated")
		}

		if err := validateJWT(rawjwt, key); err != nil {
			log.Ctx(ctx).Debug().Err(err).Msg("rejected gRPC request due to invalid JWT")
			return status.Error(codes.Unauthenticated, "invalid JWT")
		}
	}
	return nil
}

func validateJWT(rawjwt string, key []byte) error {
	tok, err := jwt.ParseSigned(rawjwt)
	if err != nil {
		return err
	}

	var claims map[string]*jwt.NumericDate
	err = tok.Claims(key, &claims)
	if err != nil {
		return err
	} else if len(claims) != 1 || claims["exp"] == nil {
		return fmt.Errorf("expected exactly one claim (exp)")
	}

	if t := claims["exp"].Time(); time.Now().After(t) {
		return fmt.Errorf("JWT expired at %s", t.Format(time.DateTime))
	}
	return nil
}
