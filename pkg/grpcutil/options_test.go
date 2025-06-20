package grpcutil

import (
	"context"
	"encoding/base64"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v3"
	"github.com/go-jose/go-jose/v3/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/reflection"
	"google.golang.org/grpc/reflection/grpc_reflection_v1alpha"
	"google.golang.org/grpc/status"

	"github.com/pomerium/pomerium/pkg/cryptutil"
)

func TestSignedJWT(t *testing.T) {
	ctx, clearTimeout := context.WithTimeout(t.Context(), time.Second*10)
	defer clearTimeout()

	li, err := net.Listen("tcp4", "127.0.0.1:0")
	if !assert.NoError(t, err) {
		return
	}
	defer li.Close()

	key := cryptutil.NewKey()
	srv := grpc.NewServer(
		grpc.StreamInterceptor(StreamRequireSignedJWT(base64.StdEncoding.EncodeToString(key))),
		grpc.UnaryInterceptor(UnaryRequireSignedJWT(base64.StdEncoding.EncodeToString(key))),
	)
	reflection.Register(srv)
	go srv.Serve(li)

	t.Run("unauthenticated", func(t *testing.T) {
		cc, err := grpc.Dial(li.Addr().String(),
			grpc.WithInsecure())
		if !assert.NoError(t, err) {
			return
		}
		defer cc.Close()

		client := grpc_reflection_v1alpha.NewServerReflectionClient(cc)

		for {
			stream, err := client.ServerReflectionInfo(ctx, grpc.WaitForReady(true))
			if !assert.NoError(t, err) {
				return
			}

			err = stream.Send(&grpc_reflection_v1alpha.ServerReflectionRequest{
				Host:           "",
				MessageRequest: &grpc_reflection_v1alpha.ServerReflectionRequest_ListServices{},
			})
			if errors.Is(err, io.EOF) {
				continue
			} else if !assert.NoError(t, err) {
				return
			}

			_, err = stream.Recv()
			if errors.Is(err, io.EOF) {
				continue
			}
			assert.Equal(t, codes.Unauthenticated, status.Code(err))

			break
		}
	})
	t.Run("authenticated", func(t *testing.T) {
		cc, err := grpc.Dial(li.Addr().String(),
			grpc.WithUnaryInterceptor(WithUnarySignedJWT(func() []byte { return key })),
			grpc.WithStreamInterceptor(WithStreamSignedJWT(func() []byte { return key })),
			grpc.WithInsecure())
		if !assert.NoError(t, err) {
			return
		}
		defer cc.Close()

		client := grpc_reflection_v1alpha.NewServerReflectionClient(cc)
		stream, err := client.ServerReflectionInfo(ctx, grpc.WaitForReady(true))
		if !assert.NoError(t, err) {
			return
		}

		err = stream.Send(&grpc_reflection_v1alpha.ServerReflectionRequest{
			Host:           "",
			MessageRequest: &grpc_reflection_v1alpha.ServerReflectionRequest_ListServices{},
		})
		if !assert.NoError(t, err) {
			return
		}

		_, err = stream.Recv()
		assert.Equal(t, codes.OK, status.Code(err))
	})
}

func TestValidateJWT(t *testing.T) {
	sign := func(t *testing.T, key []byte, claims any) string {
		t.Helper()
		signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.HS256, Key: key},
			(&jose.SignerOptions{}).WithType("JWT"))
		require.NoError(t, err)
		s, err := jwt.Signed(signer).Claims(claims).CompactSerialize()
		require.NoError(t, err)
		return s
	}

	key := cryptutil.NewKey()

	t.Run("unexpected_format", func(t *testing.T) {
		err := validateJWT("not a jwt", key)
		assert.Error(t, err)
	})
	t.Run("unexpected_claim_type", func(t *testing.T) {
		rawjwt := sign(t, key, jwt.Claims{
			Subject: "subject",
			Expiry:  jwt.NewNumericDate(time.Now().Add(time.Hour)),
		})
		err := validateJWT(rawjwt, key)
		assert.Error(t, err)
	})
	t.Run("unexpected_claim_name", func(t *testing.T) {
		rawjwt := sign(t, key, jwt.Claims{
			IssuedAt: jwt.NewNumericDate(time.Now()),
			Expiry:   jwt.NewNumericDate(time.Now().Add(time.Hour)),
		})
		err := validateJWT(rawjwt, key)
		assert.ErrorContains(t, err, "expected exactly one claim (exp)")
	})
	t.Run("no_claims", func(t *testing.T) {
		rawjwt := sign(t, key, jwt.Claims{})
		err := validateJWT(rawjwt, key)
		assert.ErrorContains(t, err, "expected exactly one claim (exp)")
	})
	t.Run("unexpected_expiry_type", func(t *testing.T) {
		rawjwt := sign(t, key, map[string]any{
			"exp": "foo",
		})
		err := validateJWT(rawjwt, key)
		assert.ErrorContains(t, err, "expected number value")
	})
	t.Run("expired", func(t *testing.T) {
		rawjwt := sign(t, key, jwt.Claims{
			Expiry: jwt.NewNumericDate(time.Now().Add(-time.Minute)),
		})
		err := validateJWT(rawjwt, key)
		assert.ErrorContains(t, err, "JWT expired")
	})
	t.Run("wrong_key", func(t *testing.T) {
		otherKey := cryptutil.NewKey()
		rawjwt := sign(t, otherKey, jwt.Claims{
			Expiry: jwt.NewNumericDate(time.Now().Add(time.Hour)),
		})

		err := validateJWT(rawjwt, key)
		assert.Error(t, err)
	})
	t.Run("ok", func(t *testing.T) {
		rawjwt := sign(t, key, jwt.Claims{
			Expiry: jwt.NewNumericDate(time.Now().Add(time.Hour)),
		})
		err := validateJWT(rawjwt, key)
		assert.NoError(t, err)
	})
}
